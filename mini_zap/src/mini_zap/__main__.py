# __main__.py
from .cli import parse_args
from .orchestrator import run

def main():
    args = parse_args()
    run(args)

if __name__ == "__main__":
    main()
