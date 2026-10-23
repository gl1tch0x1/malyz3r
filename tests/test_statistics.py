import unittest

from malware_scanner.statistics import wilson_interval


class IntervalTests(unittest.TestCase):
    def test_small_zero_error_corpus_does_not_imply_zero_population_error(self):
        interval = wilson_interval(0, 121)
        self.assertAlmostEqual(interval["lower"], 0, places=12)
        self.assertGreater(interval["upper"], 0.03)
        self.assertLess(wilson_interval(0, 4000)["upper"], 0.001)

    def test_interval_matches_known_binomial_case(self):
        interval = wilson_interval(50, 100)
        self.assertAlmostEqual(interval["lower"], 0.403831530, places=8)
        self.assertAlmostEqual(interval["upper"], 0.596168470, places=8)
        self.assertIsNone(wilson_interval(0, 0))
