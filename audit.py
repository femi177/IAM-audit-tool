import pandas as pd
import argparse
from pathlib import Path
from jinja2 import Environment
from jinja2 import FileSystemLoader

DEFAULT_STALE_DAYS = 90
DEFAULT_MAX_ROLES = 5


def load_users(path):
    df = pd.read_csv(path)

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

        if user["account_status"].lower() == "inactive":
            findings.append(
                f"[HIGH] IAM-004 {user['username']} inactive account"
            )

        if user["manager"] == "":
            findings.append(
                f"[MEDIUM] IAM-005 {user['username']} missing manager"
            )

    return findings


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

        )

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


if __name__ == "__main__":
    main()
