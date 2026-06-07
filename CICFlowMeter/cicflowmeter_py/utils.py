import math


class SummaryStatistics:
    """
    Online statistics matching Apache Commons Math SummaryStatistics.
    Uses Welford's algorithm for numerically stable variance.
    Sample variance (N-1 denominator), matching Java's default isBiasCorrected=true.
    For N < 2: variance and std return NaN (matching Apache Commons Math behaviour).
    """

    def __init__(self):
        self.n = 0
        self._sum = 0.0
        self._min = float('inf')
        self._max = float('-inf')
        self._mean = 0.0
        self._m2 = 0.0

    def add_value(self, x: float):
        self.n += 1
        self._sum += x
        if x < self._min:
            self._min = x
        if x > self._max:
            self._max = x
        delta = x - self._mean
        self._mean += delta / self.n
        self._m2 += delta * (x - self._mean)

    def get_n(self) -> int:
        return self.n

    def get_sum(self) -> float:
        return self._sum

    def get_min(self) -> float:
        # Apache Commons Math returns Double.POSITIVE_INFINITY for N=0
        return self._min if self.n > 0 else float('inf')

    def get_max(self) -> float:
        # Apache Commons Math returns Double.NEGATIVE_INFINITY for N=0
        return self._max if self.n > 0 else float('-inf')

    def get_mean(self) -> float:
        return self._mean if self.n > 0 else float('nan')

    def get_variance(self) -> float:
        if self.n < 2:
            return float('nan')
        return self._m2 / (self.n - 1)

    def get_std(self) -> float:
        v = self.get_variance()
        if math.isnan(v):
            return float('nan')
        return math.sqrt(v)
