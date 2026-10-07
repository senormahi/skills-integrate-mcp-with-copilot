import argparse
import getpass

from src.auth import hash_password, load_teacher_credentials, save_teacher_credentials


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage teacher login credentials")
    commands = parser.add_subparsers(dest="command", required=True)
    set_password = commands.add_parser(
        "set-password", help="add a teacher or replace their password"
    )
    set_password.add_argument("username")
    args = parser.parse_args()

    username = args.username.strip()
    if not username:
        parser.error("username cannot be empty")

    password = getpass.getpass("New teacher password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        parser.error("password must be at least 12 characters")
    if password != confirmation:
        parser.error("passwords do not match")

    credentials = load_teacher_credentials()
    credentials[username] = hash_password(password)
    save_teacher_credentials(credentials)
    print(f"Teacher credentials saved for {username}.")


if __name__ == "__main__":
    main()