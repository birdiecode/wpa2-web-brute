#  Copyright (c) 2025. birdiecode
#
#  This file is part of "wpa2 web brute".
#
#  OfficeControl is licensed under the MIT License.
#  See the LICENSE file for details.
from intervaltree import Interval, IntervalTree


class SuperIntervalTree(IntervalTree):
    def set_task(self, chr_list, len_pwd):
        self.add_interval(0, len(chr_list) ** len_pwd, 'wait')

    def add_interval(self, start, end, status):
        overlapping_intervals = self.overlap(start, end)
        new_intervals = []

        for interval in overlapping_intervals:
            self.remove(interval)
            if interval.begin < start:
                new_intervals.append(Interval(interval.begin, start, interval.data))
            if interval.end > end:
                new_intervals.append(Interval(end, interval.end, interval.data))

        new_intervals.append(Interval(start, end, status))
        self.update(new_intervals)
        self.merge_intervals()

    def merge_intervals(self):
        sorted_intervals = sorted(self, key=lambda iv: (iv.begin, iv.end))
        merged_intervals = []

        for interval in sorted_intervals:
            if merged_intervals and merged_intervals[-1].end >= interval.begin and merged_intervals[
                -1].data == interval.data:
                merged_intervals[-1] = Interval(merged_intervals[-1].begin, max(merged_intervals[-1].end, interval.end),
                                                interval.data)
            else:
                merged_intervals.append(interval)

        self.clear()
        self.update(merged_intervals)

    def get_task(self, col):
        ret = None
        for interval in sorted(self, key=lambda iv: iv.begin):
            if interval.data == "wait":
                self.remove(interval)
                ret = Interval(interval.begin, interval.begin + col, "work")
                self.add(ret)
                self.add(Interval(interval.begin + col, interval.end, "wait"))
                break
        self.merge_intervals()
        return ret

# test
if __name__ == "__main__":
    tree = SuperIntervalTree()
    tree.set_task(["1", "2", "a", "b", "c"], 8)
    print("\n@@@@@@@@@@@@@@@@@")
    for interval in sorted(tree):
        print(interval)

    tree.get_task(25)
    print("\n@@@@@@@@@@@@@@@@@")
    for interval in sorted(tree):
        print(interval)

    tree.add_interval(0, 5, "parsed")
    print("\n@@@@@@@@@@@@@@@@@")
    for interval in sorted(tree):
        print(interval)
