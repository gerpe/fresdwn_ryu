from ryu.cmd import manager
import sys

def main():
    sys.argv.append('main_app.py')
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()

if __name__ == '__main__':
    main()
