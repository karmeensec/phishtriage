import argparse
import json

from backend.app.analyzers.email_parser import (
    EmailValidationError,
    parse_email,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safely analyze an .eml email file."
    )

    parser.add_argument(
        "email_file",
        help="Path to the .eml file that should be analyzed.",
    )

    arguments = parser.parse_args()

    try:
        result = parse_email(arguments.email_file)
    except EmailValidationError as error:
        parser.error(str(error))

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()