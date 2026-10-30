// SPDX-License-Identifier: BSD-2-Clause
#include <iostream>
#include <numeric>
#include <vector>
int main() {
    std::vector<int> values{1, 2, 3};
    int sum = std::accumulate(values.begin(), values.end(), 0);
    std::cout << sum << "\n";
    return sum == 6 ? 0 : 1;
}
