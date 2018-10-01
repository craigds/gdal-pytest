#!/usr/bin/env python3
"""
Converts GDAL's test suite to use pytest style assertions.
"""

import argparse

from fissix.fixer_util import Comma, Newline, parenthesize, Attr, ArgList
from fissix.pygram import python_symbols as syms

from bowler import Query, TOKEN
from bowler.types import Leaf, Node

flags = {}


def kw(name, **kwargs):
    """
    A helper to produce keyword nodes
    """
    kwargs.setdefault("prefix", " ")
    return Leaf(TOKEN.NAME, name, **kwargs)


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


def parenthesize_if_necessary(node):
    # If not already parenthesized, parenthesize
    for first_leaf in node.leaves():
        if first_leaf.type in (TOKEN.LPAR, TOKEN.LBRACE, TOKEN.LSQB):
            # Already parenthesized
            return node
        break
    return parenthesize(node.clone())


def invert_condition(condition):
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
    else:
        return Node(syms.not_test, [kw("not"), parenthesize(condition.clone())])


def gdaltest_fail_reason_to_assert(node, capture, filename):
    """
    Converts an entire if statement into an assertion.

    if x == y:
        gdal.post_reason('foo')
        return 'fail'

    -->
        assert x != y, 'foo'
    """
    if flags["debug"]:
        print(f"expression: {capture}")

    condition = capture["condition"]
    reason = capture["reason"]

    returntype = capture["returntype"].value[1:-1]
    if returntype != "fail":
        # only handle fails for now, tackle others later
        return

    assertion = Assert(
        [invert_condition(condition)], reason.clone(), prefix=node.prefix
    )
    if flags["debug"]:
        print(f"Replacing:\n\t{node}")
        print(f"With: {assertion}")
        print()

    # Trailing whitespace and any comments after the if statement are captured
    # in the prefix for the dedent node. Copy it to the following node.
    dedent = capture["dedent"]
    next_node = node.next_sibling
    node.replace([assertion, Newline()])
    next_node.prefix = dedent.prefix


def gdaltest_skipfail_reason_to_if(node, capture, filename):
    """
    Updates a more complex if statement.
    Keeps it as an if statement, but adds an assertion or `pytest.skip()`.

    This handles cases where there are extra print() calls in the if statement, etc.

    if x == y:
        print('everything is broken')
        gdal.post_reason('foo')
        return 'fail'

    -->
        if x == y:
            print('everything is broken')
            assert False, 'foo'

    This also handles 'skip' cases:

    if x == y:
        gdal.post_reason('foo')
        return 'skip'

    -->
        if x == y:
            pytest.skip('foo')
    """
    if flags["debug"]:
        print(f"expression: {capture}")

    returntype = capture["returntype"].value[1:-1]
    if returntype not in ("skip", "fail"):
        return

    # Remove the gdal.post_reason() statement altogether. Preserve whitespace
    reason = [capture["reason"].clone()]
    prefix = capture["post_reason_call"].prefix
    next_node = capture["post_reason_call"].next_sibling
    capture["post_reason_call"].remove()
    next_node.prefix = prefix

    # Replace the return statement with a call to pytest.skip() or assert False
    if returntype == "skip":
        replacement = Attr(
            kw("pytest", prefix=capture["return_call"].prefix), kw("skip")
        ) + [ArgList(reason)]
    else:
        replacement = Assert(
            [kw("False")], reason, prefix=capture["return_call"].prefix
        )

    capture["return_call"].replace(replacement)


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
        dest="debug",
        default=False,
        action="store_true",
        help="Spit out debugging information",
    )
    parser.add_argument(
        "files", nargs="+", help="The python source file(s) to operate on."
    )
    args = parser.parse_args()

    # No way to pass this to .modify() callables, so we just set it at module level
    flags["debug"] = args.debug

    (
        Query(*args.files)
        # NOTE: You can append as many .select().modify() bits as you want to one query.
        # Each .modify() acts only on the .select[_*]() immediately prior.
        .select(
            """
            if_stmt<
                "if" condition=any ":"
                suite<
                    any any
                    simple_stmt<
                        power<
                            "gdaltest" trailer< "." "post_reason" >
                            trailer< "(" reason=any ")" >
                        >
                        any
                    >
                    simple_stmt<
                        return_stmt< "return" returntype=STRING >
                        any
                    >
                    dedent=any
                >
            >
        """
        )
        .modify(callback=gdaltest_fail_reason_to_assert)
        .select(
            """
            if_stmt<
                "if" any ":"
                suite<
                    any any
                    any*
                    post_reason_call=simple_stmt<
                        power<
                            "gdaltest" trailer< "." "post_reason" >
                            trailer< "(" reason=any ")" >
                        >
                        any
                    >
                    any*
                    simple_stmt<
                        return_call=return_stmt< "return" returntype=STRING >
                        any
                    >
                    any*
                    dedent=any
                >
            >
        """
        )
        .modify(callback=gdaltest_skipfail_reason_to_if)
        # Actually run all of the above.
        .execute(
            # interactive diff implies write (for the bits the user says 'y' to)
            interactive=(args.interactive and args.write),
            write=args.write,
        )
    )


if __name__ == "__main__":
    main()
