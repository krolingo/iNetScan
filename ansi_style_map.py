# ansi_style_map.py

"""
ANSI code → CSS style map for QTextEditLogger.
You can tweak colors, add 256‐color codes, backgrounds, etc.
"""

style_map = {
    # reset
    '0':             '</span>',

    # text attributes
    '1':             'font-weight:bold',
    '4':             'text-decoration:underline',

    # foreground (normal)
    '30':            'color:black',
    '31':            'color:red',
    '32':            'color:green',
    '33':            'color:yellow',
    '34':            'color:blue',
    '35':            'color:magenta',
    '36':            'color:cyan',
    '37':            'color:white',

    # foreground (bright)
    '90':            'color:grey',
    '91':            'color:lightcoral',
    '92':            'color:lightgreen',
    '93':            'color:lightyellow',
    '94':            'color:lightblue',
    '95':            'color:plum',
    '96':            'color:lightcyan',
    '97':            'color:white',

    # backgrounds (if you want)
    '40':            'background-color:black',
    '41':            'background-color:red',
    '42':            'background-color:green',
    '43':            'background-color:yellow',
    '44':            'background-color:blue',
    '45':            'background-color:magenta',
    '46':            'background-color:cyan',
    '47':            'background-color:white',
    '100':           'background-color:grey',
    '101':           'background-color:lightcoral',
}