#!/usr/bin/env python3
"""
Converts GDAL's test suite to use pytest style assertions.
"""

import argparse

from fissix.fixer_util import (
    Comma,
    Newline,
    parenthesize,
    Attr,
    ArgList,
    find_root,
    find_binding,
    touch_import,
)
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


def parenthesize_if_not_already(node):
    for first_leaf in node.leaves():
        if first_leaf.type in (TOKEN.LPAR, TOKEN.LBRACE, TOKEN.LSQB):
            # Already parenthesized
            return node
        break
    return parenthesize(node.clone())


def parenthesize_if_multiline(node):
    if is_multiline(node):
        return parenthesize_if_not_already(node)
    return node


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


def get_function_ancestor_node(node):
    """
    Returns the function node that contains the given node, or None.
    """
    parent = node
    while parent is not None and parent.type != syms.funcdef:
        parent = parent.parent
    return parent


def _rename_test(node, filename):
    """
    Renames one test to `test_<name>`
    """
    old_name = node.value
    root = find_root(node)
    def_statement = find_binding(old_name, root)

    if old_name in ("None",):
        # why are these there?
        return

    if not old_name.startswith("test_"):
        new_name = f"test_{old_name}"

        # def_statement can be None if the test doesn't exist.
        # Could happen if it was referenced in multiple places;
        # the first time we came across it we renamed it.
        if def_statement is not None:
            # Rename the function
            def_statement.children[1].value = new_name
            def_statement.children[1].changed()

        # Rename all references, including `node`
        for n in root.leaves():
            if n.type == TOKEN.NAME and n.value == old_name:
                # Don't include dotted names
                if n.parent.type == syms.trailer and n.prev_sibling and n.prev_sibling.value == '.':
                    continue

                # This is probably a reference to the test function
                # However, we need to check in case it's a separate local var.
                # Figure out if we're in a function, and see if there's a binding for
                # the same name
                func_node = get_function_ancestor_node(n)
                if func_node and find_binding(old_name, func_node):
                    # This is a local var with the same name, don't rename it
                    continue

                n.value = new_name
                n.changed()


def rename_tests(node, capture, filename):
    """
    Renames all test functions to `test_<name>` if they're not already.

    Detects tests by looking in the `gdaltest_list` var.
    """
    if flags["debug"]:
        print(f"renaming {filename} tests: {capture!r}")

    if capture.get("testname"):
        # one test
        tok = capture["testname"]
        _rename_test(tok, filename)
    else:
        # multiple tests in a list
        for tok in list(capture["testnames"].children):
            if tok.type == TOKEN.NAME:
                _rename_test(tok, filename)


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
        [invert_condition(parenthesize_if_multiline(condition))],
        parenthesize_if_multiline(reason.clone()),
        prefix=node.prefix,
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

    returntype = string_value(capture["returntype"])
    if returntype not in ("skip", "fail"):
        return

    # Remove the gdal.post_reason() statement altogether. Preserve whitespace
    reason = capture["reason"].clone()
    prefix = capture["post_reason_call"].prefix
    next_node = capture["post_reason_call"].next_sibling
    capture["post_reason_call"].remove()
    next_node.prefix = prefix

    # Replace the return statement with a call to pytest.skip() or assert False
    if returntype == "skip":
        replacement = Attr(
            kw("pytest", prefix=capture["return_call"].prefix), kw("skip", prefix="")
        ) + [ArgList([reason])]
        # Adds a 'import pytest' if there wasn't one already
        touch_import(None, "pytest", node)
    else:
        replacement = Assert(
            [kw("False")],
            parenthesize_if_multiline(reason),
            prefix=capture["return_call"].prefix,
        )

    capture["return_call"].replace(replacement)


def remove_return_success(node, capture, filename):
    """
    return 'success'
        -->
        If it's halfway through a function, it gets replaced by just `return`.
        Otherwise, it just gets removed.

    return 'success' if foo else 'fail'
        --> assert foo
    """
    if flags["debug"]:
        print(f"expression: {capture}")

    if capture.get("comparison"):
        # ternary (`return x if y else z`)
        # convert to assert statement.
        true_result = string_value(capture["true_result"])
        false_result = string_value(capture["false_result"])

        invert = False
        if true_result != "success":
            invert = True
            true_result, false_result = false_result, true_result
        if true_result != "success" or false_result != "fail":
            # dunno what this is.
            return

        comparison = capture["comparison"].clone()

        if invert:
            comparison = invert_condition(comparison)

        capture["return_call"].replace(
            Assert(
                [parenthesize_if_multiline(comparison)],
                prefix=capture["return_call"].prefix,
            )
        )
    else:
        value = string_value(capture["returnvalue"])
        if value == "success":
            # Check if it's at the end of the function
            func = node
            levels = 0
            while func.type != syms.funcdef:
                func = func.parent
                levels += 1

            if levels > 2:
                # return statement is indented, ie we can't remove it.
                # But we can replace it with a bare `return`
                capture["return_call"].replace(
                    capture["return_call"].children[0].clone()
                )
            else:
                node.remove()


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

    queries = [
        Query(*args.files)
        # 1. Rename all tests `test_*`, and removes the `gdaltest_list` assignments.
        .select(
            """
                power<
                    "gdaltest_list" trailer< "." "append" >
                    trailer< "(" testname=NAME ")" >
                >
            |
                power<
                    "gdaltest_list" trailer< "." "insert" >
                    trailer< "(" any "," testname=NAME ")" >
                >
            |
                expr_stmt< "gdaltest_list" "=" atom< "["
                    testnames=listmaker
                "]" > >
            |
                expr_stmt< "gdaltest_list" "=" atom< "("
                    testnames=testlist_gexp
                ")" > >
            """
        ).modify(rename_tests)
        # 2. Turn basic if/post_reason clauses into assertions
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
        ).modify(callback=gdaltest_fail_reason_to_assert)
        # 3. Replace further post_reason calls
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
        ).modify(callback=gdaltest_skipfail_reason_to_if),
        Query(*args.files)
        # 4. Remove all `return 'success'`, or convert ternary ones to asserts.
        .select(
            """
            simple_stmt<
                return_call=return_stmt< "return"
                    (
                        test<
                            true_result=STRING "if" comparison=any "else" false_result=STRING
                        >
                    |
                        returnvalue=STRING
                    )
                >
                any
            >
            """
        ).modify(callback=remove_return_success),
    ]

    # FIXME: running all of these as *one* query should be possible,
    # but causes strange `patch` conflict errors.
    # Need to describe the issue and report to Bowler.
    # But it works as-is, just takes a little longer.
    for q in queries:
        # Actually run all of the above.
        q.execute(
            # interactive diff implies write (for the bits the user says 'y' to)
            interactive=(args.interactive and args.write),
            write=args.write,
        )


if __name__ == "__main__":
    main()
