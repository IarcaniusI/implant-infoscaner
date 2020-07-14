import re
import sys
import praw
import argparse
import json
import random
import signal
from datetime import datetime

PROCESS_NAME = "implant-infoscaner"
NO_NOTIFY = False

# register enhancing for use: https://www.reddit.com/prefs/apps

def signal_term_handler(signal, frame):
    exit_time = datetime.now().isoformat().replace("T", " ")
    print(exit_time, '|', PROCESS_NAME, 'terminated')
    sys.exit(0)

def critical_print(*messages, action=None):
    if action is not None:
        action()

    err_time = datetime.now().isoformat().replace("T", " ")
    print(err_time, "|", *messages, file=sys.stderr)
    sys.exit()

def main():
    # handle unix signal before exiting
    signal.signal(signal.SIGTERM, signal_term_handler)
    signal.signal(signal.SIGINT, signal_term_handler)

    start_time = datetime.now().isoformat().replace("T", " ")
    print(start_time, '|', PROCESS_NAME, 'started')

    # parse command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--auth', default=["auth.conf"], nargs=1,
                        help="Path to file with auth settings.")
    parser.add_argument('-r', '--run', default=["run.conf"], nargs=1,
                        help="Path to file with run settings.")
    parser.add_argument('-n', '--no-notify', action='store_true', default=False,
                        help="Disable log notification messages (REPLIES).")
    command_arg = parser.parse_args()
    if command_arg.no_notify:
        NO_NOTIFY = True

    # set filenames for files with auth and run settings
    auth_filename = command_arg.auth[0]
    run_filename = command_arg.run[0]
    print("Auth file name: ", auth_filename)
    print("Run file name: ", run_filename)

    # load info from settings files
    auth_settings = load_auth_settings(auth_filename)
    run_settings = load_run_settings(run_filename)

    # reddit authentication
    try:
        my_user, subreddit = auth(auth_settings)
    except Exception as err:
        critical_print("Can't auth : ", err)

    # script main function executing
    try:
        process_comments_stream(my_user, subreddit, run_settings)
    except Exception as err:
        critical_print("Runtime error : ", err)

# reddit authentication, username and subreddit obtaining
# argument s - dict with auth settings
def auth(s: dict):
    reddit = praw.Reddit(user_agent=s.get("user_agent"),
                            client_id=s.get("client_id"), client_secret=s.get("client_secret"),
                            username=s.get("username"), password=s.get("password"))
    my_user = reddit.user.me()

    auth_time = datetime.now().isoformat().replace("T", " ")
    print(auth_time, "|", PROCESS_NAME, "authenticated, user name: '", my_user, "'")
    subreddit = reddit.subreddit(s.get("subreddit"))
    print("Subredit name: ", subreddit)
    return my_user, subreddit

# main sctipt function
def process_comments_stream(my_user, subreddit, run_settings: dict) -> None:
    # process every comment obtained from reddit online stream
    for comment in subreddit.stream.comments():
        comment_body = comment.body.lower()

        # don't process youself comment
        if comment.author.name != my_user.name:
            detected = process_comment(comment_body, run_settings)
            if detected is not None:
                message_subject = "THEME " + detected + " SCANNED"
                message_text = comment_body + "\nwww.reddit.com{}".format(comment.permalink)

                if not NO_NOTIFY:
                    reply_time = datetime.now().isoformat().replace("T", " ")
                    print(reply_time, "|", message_subject, ":", message_text)

                my_user.message(message_subject, message_text)


# return reply phrase if success, else None
def process_comment(comment_body: str, run_settings: dict):
    for rule in run_settings:
        success_searches = 0
        for compiled in rule.get("compiled"):
            if compiled.search(comment_body):
                success_searches += 1

        if len(rule.get("compiled")) == success_searches:
            return rule.get("theme")

    return None

# parse JSON file with  auth settings
def load_auth_settings(filename: str) -> dict:
    # read settings from JSON file
    try:
        read_file = open(filename, "r")
    except Exception as err:
        critical_print("Can't open file '", filename, "' : ", err, action=read_file.close)
    else:
        try:
            auth_settings = json.load(read_file)
        except Exception as err:
            critical_print("Impossible to parse file '", filename, "' : ", err, action=read_file.close)
    finally:
        read_file.close()

    # check type of auth settings
    auth_params = ["user_agent", "client_id", "client_secret", "username", "password" ,"subreddit"]
    if type(auth_settings) is not dict:
        critical_print("Incorrect root element in file '", filename, "'")
    else:
        for auth_param in auth_params:
            if type(auth_settings.get(auth_param)) is not str:
                critical_print("Incorrect argument '", auth_param, "' in file '", filename, "'")

    return auth_settings

# parse JSON file with  run settings
def load_run_settings(filename: str) -> list:
    # read settings from JSON file
    try:
        read_file = open(filename, "r")
    except Exception as err:
        critical_print("Can't open file '", filename, "' : ", err, action=read_file.close)
    else:
        try:
            run_settings = json.load(read_file)
        except Exception as err:
            critical_print("Impossible to parse file '", filename, "' : ", err, action=read_file.close)
    finally:
        read_file.close()

    # check type of run settings and add compiled regexes for every rule
    if type(run_settings) is not list:
        critical_print("Incorrect root element in file '", filename, "'")
    else:
        for i, rule in enumerate(run_settings):
            if type(rule) is not dict:
                critical_print("Incorrect rule '", str(i),"' in file '", filename, "'")
            else:
                if type(rule.get("theme")) is not str:
                    critical_print("Incorrect argument 'theme' in rule '", str(i),"' in file '", filename, "'")
                else:
                    rule_params = ["scanner_regexes"]
                    for rule_param in rule_params:
                        if type(rule.get(rule_param)) is not list:
                            critical_print("Incorrect argument '", rule_param, "' in rule '",
                                str(i), "' in file '", filename, "'")
                        else:
                            for value in rule.get(rule_param):
                                if type(value) is not str:
                                    critical_print("Incorrect value in list '", rule_param, "' in rule '",
                                        str(i), "' in file '", filename, "'")

    # add compiled regexes for every rule
    for rule in run_settings:
        rule["compiled"] = []
        for expr in rule.get("scanner_regexes"):
            compiled = re.compile(expr)
            rule["compiled"].append(compiled)

    return run_settings

if __name__ == "__main__":
    main()
