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


def replace_if_with_assert(if_node, dedent_node, assert_node):
    # Trailing whitespace and any comments after the if statement are captured
    # in the prefix for the dedent node. Copy it to the following node.
    next_node = if_node.next_sibling
    if_node.replace([assert_node, Newline()])
    next_node.prefix = dedent_node.prefix

    message_nodes = assert_node.children[3:]

    if message_nodes:
        # If one line, and it's longer than LONG_LINE, make a basic attempt to split before the message
        lines = str(assert_node).splitlines()
        original_num_long_lines = sum(1 for line in lines if len(line) > LONG_LINE)

        if original_num_long_lines:
            # First, clone the original.
            assert_node, split_assert = assert_node.clone(), assert_node

            # now insert a newline after the comma
            reason_node = message_nodes[0]
            reason_node.prefix = f" \\\n{find_indentation(split_assert)}    {reason_node.prefix.lstrip(' ')}"


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
                if (
                    n.parent.type == syms.trailer
                    and n.prev_sibling
                    and n.prev_sibling.value == '.'
                ):
                    continue

                # This is probably a reference to the test function
                # However, we need to check in case it's a separate local var.
                # Figure out if we're in a function, and see if there's a binding for
                # the same name
                func_node = get_ancestor_of_type(n, syms.funcdef)
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

    testnames = capture["testnames"]
    if not isinstance(testnames, list):
        testnames = [testnames]
    for testnames_node in testnames:
        if testnames_node.type == TOKEN.NAME:
            # just one test in the list
            _rename_test(testnames_node, filename)
        else:
            for tok in list(testnames_node.children):
                if tok.type == TOKEN.NAME:
                    _rename_test(tok, filename)


def remove_useless_post_reason_calls(node, capture, filename):
    reason = string_value(capture['reason']).strip().lower()
    if reason in ('skip', 'skipped', 'fail', 'failure', 'failed'):
        # kind of an unhelpful message, just don't have a message.
        next_node = node.next_sibling
        node.remove()
        next_node.prefix = node.prefix


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


def gdaltest_fail_reason_to_assert(node, capture, filename):
    """
    Converts an entire if statement into an assertion.

    if x == y:
        print("a")
        gdal.post_reason('b')
        print("c")
        return 'fail'

    -->
        assert x != y, 'foo'

    Uses post_reason(x) or print(x) as valid reasons.
    Prefers post_reason(x).
    Ignores reasons that are sub-expressions of the condition
    (ie, will ignore `x` as a reason in the above example.)

    Attempts to strip out low-value print/post_reason calls.
    If they can't all be stripped out, falls back to using an if statement with pytest.fail():

        if x == y:
            print("a", a)
            pytest.fail("b")
    """
    if flags["debug"]:
        print(f"expression: {capture}")

    returntype = string_value(capture["returntype"])
    if returntype != "fail":
        # only handle fails for now, tackle others later
        return

    condition = capture["condition"]
    condition_leaves = {
        n.value for n in condition.leaves() if n.type in (TOKEN.NAME, TOKEN.STRING)
    }

    candidates = []
    # Find a reason. Prefer post_reason reasons rather than print statements.
    for stmt in capture['reason_candidates']:
        power = stmt.children[0]
        if power.children[0].value == 'print':
            candidates.append(power.children[1].children[1])

    for stmt in capture['reason_candidates']:
        power = stmt.children[0]
        if power.children[0].value == 'gdaltest':
            candidates.append(power.children[2].children[1])
        elif power.children[0].value == 'post_reason':
            candidates.append(power.children[1].children[1])

    candidates.reverse()

    IGNORE_REASON_STRING = re.compile(
        r'(got %.* expected .*)|(.* returned %.* instead of.*)', re.I
    )
    reason = None
    for i, candidate in reversed(list(enumerate(candidates[:]))):
        # Don't include reasons that are actually expressions used in the comparison itself.
        # These are already printed by pytest in the event of the assertion failing
        candidate_leaves = {
            n.value for n in candidate.leaves() if n.type in (TOKEN.NAME, TOKEN.STRING)
        }
        if candidate_leaves.issubset(condition_leaves):
            # Reason is just made up of expressions already used in the comparison; remove it
            safe_remove_from_suite(candidate.parent.parent.parent)
            candidates.pop(i)
            continue

        if any(
            leaf.type == TOKEN.STRING and IGNORE_REASON_STRING.match(string_value(leaf))
            for leaf in candidate.leaves()
        ):
            # looks kind of useless too; pytest will output the got/expected values.
            safe_remove_from_suite(candidate.parent.parent.parent)
            candidates.pop(i)
            continue
        # Keep this reason.
        reason = candidate

    if reason:
        # remove the winning reason node from the tree
        safe_remove_from_suite(reason.parent.parent.parent)
        reason.remove()
        candidates.remove(reason)

    if not candidates:
        # all print/post_reason calls were removed.
        # So we can convert the if statement to an assert.
        if reason:
            reason = parenthesize_if_not_already(reason.clone())
        assertion = Assert(
            [parenthesize_if_multiline(invert_condition(condition))],
            reason,
            prefix=node.prefix,
        )
        if flags["debug"]:
            print(f"Replacing:\n\t{node}")
            print(f"With: {assertion}")
            print()

        replace_if_with_assert(node, capture['dedent'], assertion)
    else:
        # At least one print statement remains.
        # We need to keep the if statement, and use a `pytest.fail(reason)`.
        replacement = Attr(
            kw("pytest", prefix=capture["return_call"].prefix),
            kw(returntype, prefix=""),
        ) + [ArgList(listify(reason))]

        # Adds a 'import pytest' if there wasn't one already
        touch_import(None, "pytest", node)

        capture["return_call"].replace(replacement)


def gdaltest_other_skipfails(node, capture, filename):
    """
    Replaces a generic call to `return 'skip'` or `return 'fail'`,
    with a `pytest.skip()` or `pytest.fail()`.

    If there's a call to `gdal.post_reason()` immediately preceding
    the return statement, uses that reason as the argument to the
    skip/fail function.
    Ignores/preserves print() calls between the two.

    Examples:

        gdal.post_reason('foo')
        print('everything is broken')
        return 'fail'
        -->
            print('everything is broken')
            pytest.fail('foo')


        gdal.post_reason('foo')
        return 'skip'
        -->
            pytest.skip('foo')


        return 'skip'
        -->
            pytest.skip()
    """
    if flags["debug"]:
        print(f"expression: {capture}")

    returntype = string_value(capture["returntype"])
    if returntype not in ("skip", "fail"):
        return

    reason = None
    if capture.get('post_reason_call'):
        # Remove the gdal.post_reason() statement altogether. Preserve whitespace
        reason = capture["reason"].clone()
        prefix = capture["post_reason_call"].prefix
        next_node = capture["post_reason_call"].next_sibling
        capture["post_reason_call"].remove()
        next_node.prefix = prefix

    # Replace the return statement with a call to pytest.skip() or pytest.fail().
    # Include the reason message if there was one.
    replacement = Attr(
        kw("pytest", prefix=capture["return_call"].prefix), kw(returntype, prefix="")
    ) + [ArgList(listify(reason))]

    # Adds a 'import pytest' if there wasn't one already
    touch_import(None, "pytest", node)

    capture["return_call"].replace(replacement)


def remove_node_and_fix_empty_functions(node):
    """
    After removing a node from a function, it might possibly be empty.
    So call this to remove the node, then (if needed) add a 'pass' statement
    """
    suite = get_ancestor_of_type(node, syms.suite)
    for c in suite.children:
        if c != node and c.type not in (TOKEN.DEDENT, TOKEN.INDENT, TOKEN.NEWLINE):
            node.remove()
            return

    # No children. Add a `pass`
    node.replace(Leaf(TOKEN.NAME, 'pass'))


def remove_success_expectations(node, capture, filename):
    """
    We're about to remove the 'success' return value of all the helpers,
    and just let them pytest.fail() themselves.

    So we need to remove where tests are expecting them to return 'success'.

    if x() != 'success':
        return 'fail'

    --> x()
    """

    if capture['returntype'].type not in (TOKEN.STRING, TOKEN.NAME):
        return

    if capture['x'].type == TOKEN.NAME:
        # `if ret == 'success'`.
        # We can just remove this.

        if (
            capture['returntype'] == TOKEN.NAME
            and capture['returntype'].value != capture['x'].value
        ):
            # not sure what this is doing? leave it alone.
            return

        # Trailing whitespace and any comments after the if statement are captured
        # in the prefix for the dedent node. Copy it to the following node.
        dedent = capture["dedent"]
        next_node = node.next_sibling
        node.remove()
        next_node.prefix = dedent.prefix
    elif capture['x'].type == syms.power:
        # is a function call. call it, just discard the result.
        if capture['returntype'].type == TOKEN.NAME:
            # not sure what this is doing? leave it alone
            return
        func = capture['x'].clone()
        func.prefix = node.prefix

        # Trailing whitespace and any comments after the if statement are captured
        # in the prefix for the dedent node. Copy it to the following node.
        dedent = capture["dedent"]
        next_node = node.next_sibling
        node.replace([func, Newline()])
        next_node.prefix = dedent.prefix
    else:
        print(capture['x'])
        raise ValueError("unknown type")


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
                remove_node_and_fix_empty_functions(node)


def remove_test_lists(node, capture, filename):
    """
    Removes the `gdaltest_list` from modules.
    """
    node.remove()


def remove_main_block(node, capture, filename):
    """
    Removes the `__main__` block from modules.
    """
    node.remove()


def make_pytest_raises_blocks(node, capture, filename):
    """
    Turns this:

        try:
            ...
            pytest.fail(...)
        except:
            pass

    Into:
        with pytest.raises(Exception):
            ...

    Not only is this prettier, but the former is a bug since
    pytest.fail() raises an exception.
    """

    exc_class = capture.get('exc_class', None)

    if exc_class:
        exc_class = exc_class.clone()
        exc_class.prefix = ''
        raises_args = [exc_class]
    else:
        raises_args = [kw('Exception', prefix='')]

    reason = capture.get('reason')
    if reason:
        assert len(reason) == 1
        reason = KeywordArg(kw('message'), reason[0].clone())
        raises_args = [Node(syms.arglist, raises_args + [Comma(), reason])]

    raises_args = [LParen()] + raises_args + [RParen()]

    capture['fail_stmt'].remove()

    try_suite = capture['try_suite'].clone()

    with_stmt = Node(
        syms.with_stmt,
        [
            kw('with', prefix=''),
            Node(
                syms.power,
                [
                    kw('pytest'),
                    Node(syms.trailer, [Dot(), kw('raises', prefix='')]),
                    Node(syms.trailer, raises_args),
                ],
            ),
            Leaf(TOKEN.COLON, ':'),
            try_suite,
        ],
        prefix=node.prefix,
    )

    # Trailing whitespace and any comments after the if statement are captured
    # in the prefix for the dedent node. Copy it to the following node.
    dedent = capture["dedent"]
    next_node = node.next_sibling

    # This extra newline avoids syntax errors in some cases (where the try
    # statement is at the end of another suite)
    # I don't really know why those occur.
    # Should clean this stuff up with `black` later.
    node.replace([with_stmt, Newline()])
    next_node.prefix = dedent.prefix


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
        "--step", default=False, action="store", type=int, help="Which step to run"
    )
    parser.add_argument(
        "files", nargs="+", help="The python source file(s) to operate on."
    )
    args = parser.parse_args()

    # No way to pass this to .modify() callables, so we just set it at module level
    flags["debug"] = args.debug

    query = Query(*args.files)

    steps = {
        # Rename all tests `test_*`, and removes the `gdaltest_list` assignments.
        0: lambda q: q.select(
            """
            expr_stmt< "gdaltest_list" "=" atom< "["
                testnames=( listmaker | NAME )
            "]" > >
            """
        ).modify(rename_tests),
        # `if x() != 'success'` --> `x()` (the 'success' return value gets removed further down)
        1: lambda q: q.select(
            """
            if_stmt<
                "if" comparison<
                    x=any "!=" ( "'success'" | '"success"' )
                > ":"
                suite<
                    any any
                    [
                        simple_stmt<
                            power<
                                (
                                    "gdaltest" trailer< "." "post_reason" >
                                |
                                    "post_reason"
                                )
                                trailer< "(" reason=( "'failure'" | "'fail'" | "'failed'" | '"fail"' | '"failed"' | '"failure"' ) ")" >
                            >
                            any
                        >
                    ]
                    simple_stmt<
                        return_stmt< "return" returntype=any >
                        any
                    >
                    dedent=any
                >
            >
            """
        ).modify(callback=remove_success_expectations),
        # Remove useless `post_reason('fail')` calls
        2: lambda q: q.select(
            """
            simple_stmt<
                power<
                    (
                        "gdaltest" trailer< "." "post_reason" >
                    |
                        "post_reason"
                    )
                    trailer< "(" reason=STRING ")" >
                >
                any
            >
        """
        ).modify(callback=remove_useless_post_reason_calls),
        # Turn basic if/post_reason clauses into assertions
        3: lambda q: q.select(
            f"""
            if_stmt<
                "if" condition=any ":"
                suite<
                    any any
                    reason_candidates=(
                        simple_stmt<
                            (
                                power<
                                    (
                                        "gdaltest" trailer< "." "post_reason" >
                                    |
                                        "post_reason"
                                    )
                                    trailer
                                >
                            |
                                power<
                                    "print"
                                    trailer
                                >
                            )
                            any
                        >
                    )*
                    simple_stmt<
                        return_call=return_stmt< "return" returntype=STRING >
                        any
                    >
                    dedent=any
                >
            >
        """.format(
                print='''print=simple_stmt< power< "print" trailer< "(" reason=any ")" > > any >'''
            )
        ).modify(callback=gdaltest_fail_reason_to_assert),
        # Replace further post_reason calls and skip/fail returns
        4: lambda q: (
            q.select(
                """
                    any<
                        any*
                        post_reason_call=simple_stmt<
                            power<
                                (
                                    "gdaltest" trailer< "." "post_reason" >
                                |
                                    "post_reason"
                                )
                                trailer< "(" reason=any ")" >
                            >
                            any
                        >
                        any*
                        return_stmt=simple_stmt<
                            return_call=return_stmt< "return" returntype=STRING >
                            any
                        >
                        any*
                    >
                """
            )
            .modify(callback=gdaltest_other_skipfails)
            # (still part of step 4)
            # same as above, but get the reason from `print(reason)`
            # if we didn't find a post_reason clause.
            # (and, now, the reason is optional)
            .select(
                """
                    any<
                        any*
                        [
                            post_reason_call=simple_stmt<
                                power<
                                    (
                                        "print"
                                    )
                                    trailer< "(" reason=any ")" >
                                >
                                any
                            >
                            any*
                        ]
                        return_stmt=simple_stmt<
                            return_call=return_stmt< "return" returntype=STRING >
                            any
                        >
                        any*
                    >
                """
            )
            .modify(callback=gdaltest_other_skipfails)
        ),
        # Remove all `return 'success'`, or convert ternary ones to asserts.
        5: lambda q: q.select(
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
        # Remove gdaltest_list from each test module
        6: lambda q: q.select(
            """
            simple_stmt<
                expr_stmt< "gdaltest_list" "=" atom< "["
                    testnames=listmaker
                "]" > >
                any
            >
            """
        ).modify(remove_test_lists),
        # Remove the __main__ block from each test module
        7: lambda q: q.select(
            """
            if_stmt<
                "if"
                comparison< "__name__" "==" "'__main__'" >
                any*
            >
            """
        ).modify(remove_main_block),
        # Find pytest.fail() inside `try` blocks
        # where the 'except' bit is just "pass",
        # and turn them into `with pytest.raises(...)` blocks
        8: lambda q: q.select(
            """
            try_stmt<
                "try" ":"
                try_suite=suite<
                    any any
                    any*
                    fail_stmt=simple_stmt<
                        power<
                            "pytest"
                            trailer< "." "fail" >
                            trailer< "(" reason=any* ")" >
                        >
                        any
                    >
                    any
                >
                ("except" | except_clause< "except" exc_class=NAME any* > ) ":"
                suite<
                    any any
                    simple_stmt<
                        "pass"
                        any
                    >
                    dedent=any
                >
            >
            """
        ).modify(make_pytest_raises_blocks),
    }

    if args.step is not None:
        query = steps[args.step](query)
    else:
        for i in sorted(steps.keys()):
            query = steps[i](query)

    query.execute(
        # interactive diff implies write (for the bits the user says 'y' to)
        interactive=(args.interactive and args.write),
        write=args.write,
        silent=args.silent,
    )


if __name__ == "__main__":
    main()
