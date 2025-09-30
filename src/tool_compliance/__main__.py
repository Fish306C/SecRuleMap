from .orchestrator.orchestrator import run
from .cli import parse_args

if __name__ == "__main__":
    args = parse_args()
    run(args)