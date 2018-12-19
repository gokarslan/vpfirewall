#!/usr/bin/env python

import matplotlib.pyplot as plt

def pplot(x, y, lbl):
    plt.xticks(x)
    plt.xlabel('Number of Threads')
    plt.ylabel('Kbit/s')
    plt.plot(x, y, '-*', label=lbl)

plt.ylim(550, 680)
pplot([1, 4, 8, 16, 24, 32, 64], [645, 660, 666, 665, 675, 670, 670], '1 fw rule') # 1
pplot([1, 4, 8, 16, 24, 32, 64], [631, 645, 656, 660, 665, 675, 670], '10 fw rules') # 10
pplot([1, 4, 8, 16, 24, 32, 64], [618, 639, 657, 660, 654, 660, 660], '25 fw rules') # 25
pplot([1, 4, 8, 16, 24, 32, 64], [611, 628, 648, 644, 650, 653, 655], '100 fw rules') # 100
pplot([1, 4, 8, 16, 24, 32, 64], [619, 631, 645, 655, 660, 655, 660], '500 fw rules') # 500
pplot([1, 4, 8, 16, 24, 32, 64], [560, 608, 620, 640, 646, 650, 650], '1000 fw rules') # 1000
plt.legend(loc="lower right")
plt.show()
