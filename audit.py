import pandas as pd
import argparse
from pathlib import Path
from jinja2 import Environment
from jinja2 import FileSystemLoader

DEFAULT_STALE_DAYS = 90
DEFAULT_MAX_ROLES = 5

REQUIRED_COLUMNS = [

    "username",

    "full_name",

    "department",

    "roles",

    "last_login_days_ago",

    "mfa_enabled",

    "account_status",

    "manager"

]

SOD_CONFLICTS = [

    ("Finance_Approver_L3", "Payroll_Admin"),

    ("HR_Admin", "Finance_Approver_L3"),

    ("IT_Admin", "Security_Admin"),

    ("Admin_Global", "Finance_Approver_L3")

]

VALID_ACCOUNT_STATUS = {

    "active",

    "inactive",

    "disabled"

}

SEVERITY_SCORE = {

    "CRITICAL": 5,

    "HIGH": 3,

    "MEDIUM": 1

}


def validate_csv(df):

    missing = [

        column

        for column in REQUIRED_COLUMNS

        if column not in df.columns

    ]

    if missing:

        raise ValueError(

            f"Missing required columns: "

            f"{', '.join(missing)}"

        )

    if df.empty:

        raise ValueError(

            "CSV contains no user records."

        )

    invalid_status = (

        df["account_status"]

        .astype(str)

        .str.lower()

        .str.strip()

    )

    bad = [

        value

        for value in invalid_status.unique()

        if value and value not in VALID_ACCOUNT_STATUS

    ]

    if bad:

        raise ValueError(

            f"Invalid account status values: "

            f"{', '.join(bad)}"

        )


def load_users(path):

    try:

        df = pd.read_csv(path)

    except FileNotFoundError:

        raise FileNotFoundError(

            f"Input file not found: {path}"
        )

    except Exception as exc:

        raise RuntimeError(
            f"Failed to read CSV: {exc}"
        )

    validate_csv(df)

    df["account_status"] = (

        df["account_status"]

        .astype(str)

        .str.lower()

        .str.strip()

    )

    df["mfa_enabled"] = (
        df["mfa_enabled"]
        .astype(str)
        .str.lower()
        .isin(["true", "1", "yes"])
    )

    df["roles_list"] = df["roles"].apply(
        lambda x: [r.strip() for r in str(x).split(",") if r.strip()]
    )

    df["role_count"] = df["roles_list"].apply(len)

    df["manager"] = (
        df["manager"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    return df


def run_checks(df):

    findings = []

    for _, user in df.iterrows():

        if user["last_login_days_ago"] > DEFAULT_STALE_DAYS:
            findings.append(
                f"[HIGH] IAM-001 {user['username']} stale account"
            )

        if user["role_count"] >= DEFAULT_MAX_ROLES:
            findings.append(
                f"[CRITICAL] IAM-002 {user['username']} excessive roles"
            )

        if not user["mfa_enabled"]:
            findings.append(
                f"[CRITICAL] IAM-003 {user['username']} MFA disabled"
            )

        if user["account_status"] == "inactive":
            findings.append(
                f"[HIGH] IAM-004 {user['username']} inactive account"
            )

        if user["manager"] == "":

            findings.append(

                f"[MEDIUM] IAM-005 "

                f"{user['username']} "
                f"missing manager"

            )

        if (

            has_admin_role(

                user["roles_list"]

            )

            and

            user["last_login_days_ago"]

            > DORMANT_ADMIN_DAYS

        ):

            findings.append(

                f"[CRITICAL] IAM-006 "

                f"{user['username']} "

                f"dormant privileged account"

            )

        if (

            has_admin_role(

                user["roles_list"]

            )

            and

            not user["mfa_enabled"]

        ):

            findings.append(

                f"[CRITICAL] IAM-007 "

                f"{user['username']} "

                f"privileged account without MFA"


            )

        for role1, role2 in SOD_CONFLICTS:
            if (

                role1 in user["roles_list"]

                and

                role2 in user["roles_list"]

            ):
                findings.append(

                    f"[HIGH] IAM-008 "

                    f"{user['username']} "

                    f"SoD conflict: "

                    f"{role1} + {role2}"

                )

    return findings


def build_rule_summary(findings):

    rules = {
        "IAM-001": "Stale Account",
        "IAM-002": "Excessive Roles",
        "IAM-003": "MFA Disabled",
        "IAM-004": "Inactive Account",
        "IAM-005": "Missing Manager",
        "IAM-006": "Dormant Privileged Account",
        "IAM-007": "Privileged Account without MFA",
        "IAM-008": "Segregation of Duties Conflict",
    }

    counts = {rule: 0 for rule in rules}

    for finding in findings:

        for rule in rules:

            if rule in finding:
                counts[rule] += 1

    return [

        {
            "rule": rule,
            "name": rules[rule],
            "count": counts[rule]
        }

        for rule in rules

    ]


def score_users(findings):

    scores = {}

    for finding in findings:

        username = finding.split()[2]

        severity = (

            finding

            .split("]")[0]

            .replace("[", "")

        )

        scores[username] = (

            scores.get(

                username,

                0

            )

            +

            SEVERITY_SCORE[severity]

        )

    return scores


ADMIN_ROLE_KEYWORDS = {

    "Admin",

    "IT_Admin",

    "SOC_Manager",

    "Executive_Full"

}


DORMANT_ADMIN_DAYS = 30


def has_admin_role(roles):

    return any(

        role in ADMIN_ROLE_KEYWORDS

        for role in roles

    )


def generate_html(findings):

    env = Environment(

        loader=FileSystemLoader(

            "templates"

        )

    )

    template = env.get_template(

        "report_template.html"

    )

    html = template.render(

        findings=findings,

        total_findings=len(findings),

        critical=sum(

            "CRITICAL" in f

            for f in findings

        ),

        high=sum(

            "HIGH" in f

            for f in findings

        ),

        medium=sum(

            "MEDIUM" in f

            for f in findings

        ),
        rules=build_rule_summary(findings)

    )

    Path(

        "reports/report.html"

    ).write_text(

        html,

        encoding="utf-8"

    )


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        default="users.csv"
    )

    args = parser.parse_args()

    df = load_users(args.input)

    findings = run_checks(df)

    scores = score_users(findings)

    generate_html(findings)

    print("\nHTML report generated")
    print("reports/report.html")

    print("\nIAM Audit Tool")
    print("------------------------------")
    print(f"Users analysed : {len(df)}\n")

    for finding in findings:
        print(finding)

    crit = sum("CRITICAL" in f for f in findings)
    high = sum("HIGH" in f for f in findings)
    med = sum("MEDIUM" in f for f in findings)

    print("\nSummary")
    print("------------------------------")
    print(f"Critical : {crit}")
    print(f"High     : {high}")
    print(f"Medium   : {med}")
    print(f"Total    : {len(findings)}")
    print("------------------------------")

    for username, score in sorted(

        scores.items(),

        key=lambda x: x[1],

        reverse=True

    )[:5]:

        print(

            f"{username:<15}"

            f"{score}"

        )


if __name__ == "__main__":
    main()
