#!/usr/bin/env python3
"""
Converts GDAL's test suite to use pytest style assertions.
"""

import argparse

from fissix.fixer_util import Comma, find_indentation, Newline
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


# TODO : Add this to fissix.fixer_util
def Assert(test, message=None, **kwargs):
    """Build an assertion statement"""
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


def gdaltest_reason_to_assert(node, capture, filename):
    if flags["debug"]:
        print("expression: %s" % capture)

    condition = capture["condition"]
    reason = capture["reason"]

    returntype = capture["returntype"].value[1:-1]
    if returntype != "fail":
        # only handle fails for now, tackle others later
        return

    assertion = Assert([condition.clone()], reason.clone(), prefix=node.prefix)
    if flags["debug"]:
        print(f"Replacing:\n\t{node}")
        print(f"With: {assertion}")
        print()

    # TODO: handle if statements with `else` blocks; atm this causes syntax errors there!
    # FIXME: why is this munging indentation on the next line in the first place?
    #        it also seems to remove comments immediately following the if statement.
    indent_next_line = find_indentation(node.next_sibling)
    node.replace([assertion, Newline(), Leaf(TOKEN.INDENT, indent_next_line)])


def main():
    parser = argparse.ArgumentParser(
        description="Converts x-unit style tests to be pytest-style where possible."
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
        "--skip-multiline-expressions",
        default=False,
        action="store_true",
        help=(
            "Skip handling lines that contain multiline expressions. "
            "The code isn't yet able to handle them well. Output is valid but not pretty"
        ),
    )
    parser.add_argument(
        "files", nargs="+", help="The python source file(s) to operate on."
    )
    args = parser.parse_args()

    # No way to pass this to .modify() callables, so we just set it at module level
    flags["debug"] = args.debug
    flags["skip_multiline_expressions"] = args.skip_multiline_expressions

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
                            trailer< "(" reason=STRING ")" >
                        >
                        any
                    >
                    simple_stmt<
                        return_stmt< "return" returntype=STRING >
                        any
                    >
                    any
                >
            >
        """
        ).modify(callback=gdaltest_reason_to_assert)
        # Actually run all of the above.
        .execute(
            # interactive diff implies write (for the bits the user says 'y' to)
            interactive=(args.interactive and args.write),
            write=args.write,
        )
    )


if __name__ == "__main__":
    main()
