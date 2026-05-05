from artifactscope.cli import build_parser


def test_report_alias_enables_single_flag_without_ambiguity():
    parser = build_parser()
    args = parser.parse_args(["target.img", "--report", "--mount-git"])
    assert args.report is True
    assert args.mount is True
