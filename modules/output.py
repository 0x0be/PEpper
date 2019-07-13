from . import colors

# print the output


def get():
    print("\n------------------------------- {0:^13}{1:3}".format(
        "DONE", " -------------------------------"))
    print(colors.GREEN + "[" + str('\u2713') + "]" +
          colors.DEFAULT + " Output written in output.csv")
