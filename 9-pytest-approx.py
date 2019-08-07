#!/usr/bin/env python3
"""
Converts GDAL's test suite to use pytest style assertions.
"""

import argparse
import re

from fissix.fixer_util import (
    Comma,
    Newline,
    parenthesize,
    Attr,
    ArgList,
    find_root,
    find_binding,
    touch_import,
    Dot,
    LParen,
    RParen,
    KeywordArg,
    find_indentation,
)
from fissix.pygram import python_symbols as syms

from bowler import Query, TOKEN
from bowler.types import Leaf, Node

flags = {}


LONG_LINE = 88  # chars


def kw(name, **kwargs):
    """
    A helper to produce keyword nodes
    """
    kwargs.setdefault("prefix", " ")
    return Leaf(TOKEN.NAME, name, **kwargs)


def string_value(s):
    """
    Removes quotes and modifiers from a string literal,
    returning just the actual value.
    """
    if not isinstance(s, str):
        s = s.value
    quote = s[-1]
    return s.split(quote, 1)[1][:-1]


def Assert(test, message=None, **kwargs):
    """
    Build an assertion statement
    """
    if not isinstance(test, list):
        test = [test]
    test[0].prefix = " "
    if message is not None:
        if not isinstance(message, list):
            message = [message]
        message.insert(0, Comma())
        message[1].prefix = " "

    return Node(
        syms.assert_stmt,
        [Leaf(TOKEN.NAME, "assert")] + test + (message or []),
        **kwargs,
    )


def is_multiline(node):
    if isinstance(node, list):
        return any(is_multiline(n) for n in node)

    for leaf in node.leaves():
        if "\n" in leaf.prefix:
            return True
    return False


def _parenthesize(node):
    """
    Same as the fissix one but doesn't do stupid things with whitespace
    """
    orig_prefix = node.prefix
    node = node.clone()
    node.prefix = ''
    ret = parenthesize(node)
    ret.prefix = orig_prefix
    return ret


def parenthesize_if_not_already(node):
    if isinstance(node, Leaf) or node.type == syms.power:
        # don't have to parenthesize, it's a simple leaf node, or a function call
        return node
    for first_leaf in node.leaves():
        if first_leaf.type in (TOKEN.LPAR, TOKEN.LBRACE, TOKEN.LSQB):
            # Already parenthesized
            return node
        break
    return _parenthesize(node)


def parenthesize_if_multiline(node):
    if is_multiline(node):
        return parenthesize_if_not_already(node)
    return node


def _num_negations(node):
    return len(
        [
            1
            for leaf in node.leaves()
            if (
                (leaf.type == TOKEN.NOTEQUAL)
                or (leaf.type == TOKEN.NAME and leaf.value == 'not')
            )
        ]
    )


def invert_condition(condition, nested=False):
    """
    Inverts a boolean expression, e.g.:
        a == b
        --> a != b

        a > b
        --> a <= b

        a or b
        --> not (a or b)

        (a or b)
        --> not (a or b)

        (a and b)
        --> not (a and b)

        (a == b and c != d)
        --> (a != b or c == d)

        a if b else c
        --> not (a if b else c)
    """
    if condition.type == syms.comparison:
        a, op, b = condition.children
        op = condition.children[1]
        if op.type == syms.comp_op:
            if (op.children[0].value, op.children[1].value) == ("is", "not"):
                return Node(syms.comparison, [a.clone(), kw("is"), b.clone()])
            elif (op.children[0].value, op.children[1].value) == ("not", "in"):
                return Node(syms.comparison, [a.clone(), kw("in"), b.clone()])
            else:
                raise NotImplementedError(f"unknown comp_op: {op!r}")
        else:
            inversions = {
                "is": Node(syms.comp_op, [kw("is"), kw("not")], prefix=" "),
                "in": Node(syms.comp_op, [kw("not"), kw("in")], prefix=" "),
                "==": Leaf(TOKEN.NOTEQUAL, "!=", prefix=" "),
                "!=": Leaf(TOKEN.EQEQUAL, "==", prefix=" "),
                ">": Leaf(TOKEN.LESSEQUAL, "<=", prefix=" "),
                "<": Leaf(TOKEN.GREATEREQUAL, ">=", prefix=" "),
                "<=": Leaf(TOKEN.GREATER, ">", prefix=" "),
                ">=": Leaf(TOKEN.LESS, "<", prefix=" "),
            }
            return Node(syms.comparison, [a.clone(), inversions[op.value], b.clone()])
    elif condition.type == syms.not_test:
        # `not x` --> just remove the `not`
        return condition.children[1].clone()
    elif condition.type in (syms.and_test, syms.or_test):
        # Tricky one.
        # (a != b and c != d)
        # which should this become?
        #    --> (a == b or c == d)
        #    --> not (a != b and c != d)
        # Seems somewhat context dependent. Basically we compute both, and then
        # decide based on which has the least negations.

        simply_inverted = Node(
            syms.not_test, [kw("not"), parenthesize_if_not_already(condition.clone())]
        )
        if condition.type == syms.and_test:
            children = [invert_condition(condition.children[0], nested=True)]
            for child in condition.children[2::2]:
                children.extend([kw('or'), invert_condition(child, nested=True)])

            complex_inverted = Node(syms.or_test, children)
            if nested:
                # We're inside an outer 'and' test, and 'or' has lower precedence.
                # so we need to parenthesize to ensure the expression is correct
                complex_inverted = _parenthesize(complex_inverted)
        else:
            children = [invert_condition(condition.children[0], nested=True)]
            for child in condition.children[2::2]:
                children.extend([kw('and'), invert_condition(child, nested=True)])

            complex_inverted = Node(syms.and_test, children)

        return min([simply_inverted, complex_inverted], key=_num_negations)
        if len(str(simply_inverted)) < len(str(complex_inverted)):
            return simply_inverted
        else:
            return complex_inverted
    else:
        return Node(
            syms.not_test, [kw("not"), parenthesize_if_not_already(condition.clone())]
        )


def get_ancestor_of_type(node, typ):
    """
    Returns the closest ancestor of the given type, or None.
    """
    parent = node
    while parent is not None and parent.type != typ:
        parent = parent.parent
    return parent


def listify(captured):
    if captured is None:
        return []
    if isinstance(captured, list):
        return captured
    else:
        return [captured]


def safe_remove_from_suite(stmt):
    prev = stmt.prev_sibling
    nek = stmt.next_sibling
    stmt.remove()
    if prev.type == TOKEN.INDENT:
        # weird case where indentation gets doubled when you remove the first
        # statement in a suite.
        nek.prefix = nek.prefix.lstrip()


def pytest_approx(node, capture, filename):
    target_value = listify(capture['target_value'])[0].clone()
    target_value.prefix = ''
    abs_tolerance = capture['abs_tolerance'].clone()
    abs_tolerance.prefix = ''
    op_value = listify(capture['op'])[0].value

    # Adds a 'import pytest' if there wasn't one already
    touch_import(None, "pytest", node)

    if op_value in ('<', '<='):
        # as you'd expect in an assert statement
        operator = Leaf(TOKEN.EQEQUAL, '==', prefix=' ')
    else:
        # probably in an if statement
        operator = Leaf(TOKEN.NOTEQUAL, '!=', prefix=' ')

    node.replace(
        Node(
            syms.comparison,
            [
                capture['lhs'].clone(),
                operator,
                Node(
                    syms.power,
                    [
                        kw('pytest'),
                        Node(
                            syms.trailer,
                            [Leaf(TOKEN.DOT, ".", prefix=''), kw('approx', prefix='')],
                            prefix='',
                        ),
                        ArgList(
                            [
                                target_value,
                                Comma(),
                                KeywordArg(kw('abs'), abs_tolerance),
                            ]
                        ),
                    ],
                ),
            ],
            prefix=node.prefix,
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Converts GDAL's test assertions to be pytest-style where possible."
    )
    parser.add_argument(
        "--no-input",
        dest="interactive",
        default=True,
        action="store_false",
        help="Non-interactive mode",
    )
    parser.add_argument(
        "--no-write",
        dest="write",
        default=True,
        action="store_false",
        help="Don't write the changes to the source file, just output a diff to stdout",
    )
    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Spit out debugging information",
    )
    parser.add_argument(
        "--silent",
        default=False,
        action="store_true",
        help="Don't spit out a diff, just write changes to files",
    )
    parser.add_argument(
        "files", nargs="+", help="The python source file(s) to operate on."
    )
    args = parser.parse_args()

    # No way to pass this to .modify() callables, so we just set it at module level
    flags["debug"] = args.debug

    (
        Query(*args.files)
        .select(
            """
            comparison<
                power<
                    "abs"
                    trailer<
                        "("
                            arith_expr<
                                lhs=any
                                "-"
                                target_value=any
                            >
                        ")"
                    >
                >
                op=( "<=" | "<" | ">" | ">=" )
                abs_tolerance=NUMBER
            >
            """
        )
        .modify(pytest_approx)
    ).execute(
        # interactive diff implies write (for the bits the user says 'y' to)
        interactive=(args.interactive and args.write),
        write=args.write,
        silent=args.silent,
    )


if __name__ == "__main__":
    main()
