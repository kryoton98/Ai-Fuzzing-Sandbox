import sys

def main():
    try:
        data = input()
    except EOFError:
        print("[victim] stdin closed", file=sys.stderr)
        sys.exit(1)

    if data == "CRASH":
        print("[victim] CRASH -> triggering ZeroDivisionError", file=sys.stderr)
        # Deliberate unhandled exception — exits with code 1 and a traceback
        result = 1 / 0  # noqa: F841

    elif data == "LOOP":
        print("[victim] LOOP -> spinning forever", file=sys.stderr)
        while True:
            pass  # infinite spin — killed by sandbox timeout

    else:
        print(f"Safe: {data}")

if __name__ == "__main__":
    main()
