"""No resource may grow; ordinary release must not be called a leak."""
import unittest
from os_cosmic_workspace_probe import compare_shared_resources, popup_recovered


class SharedRecovery(unittest.TestCase):
    def setUp(self):
        self.baseline = dict(objects=23, pages=133, mappings=41, description_refs=23,
            mapping_refs=41, grant_reserved=0, grant_used=133, free_pages=3963,
            metadata_capacity=32, page_capacity=4096)

    def test_equal_and_real_release_keep_exact_deltas(self):
        equal = compare_shared_resources(self.baseline, self.baseline)
        self.assertTrue(equal['nonincreasing'])
        self.assertTrue(equal['baseline_equal'])
        released = dict(self.baseline, objects=22, pages=125, mappings=40,
            description_refs=22, mapping_refs=40, grant_used=125, free_pages=3971)
        value = compare_shared_resources(self.baseline, released)
        self.assertTrue(value['nonincreasing'])
        self.assertFalse(value['baseline_equal'])
        self.assertEqual(value['deltas'], dict(objects=-1, pages=-8, mappings=-1,
            description_refs=-1, mapping_refs=-1, grant_reserved=0, grant_used=-8,
            free_pages=8, metadata_capacity=0, page_capacity=0))

    def test_each_individual_usage_increase_is_rejected_even_if_another_decreases(self):
        for key in ('objects', 'pages', 'mappings', 'description_refs', 'mapping_refs',
                    'grant_reserved', 'grant_used'):
            with self.subTest(key=key):
                current = dict(self.baseline)
                current['pages' if key != 'pages' else 'objects'] -= 1
                current[key] += 1
                self.assertFalse(compare_shared_resources(self.baseline, current)['nonincreasing'])

    def test_free_decrease_capacity_drift_and_unknown_or_missing_counters_fail(self):
        self.assertFalse(compare_shared_resources(self.baseline,
            dict(self.baseline, free_pages=3962))['nonincreasing'])
        mutations = []
        for key in ('metadata_capacity', 'page_capacity'):
            for delta in (-1, 1):
                mutations.append(dict(self.baseline, **{key: self.baseline[key] + delta}))
        for key in self.baseline:
            missing = dict(self.baseline); del missing[key]; mutations.append(missing)
        mutations.append(dict(self.baseline, unknown=0))
        mutations.extend(dict(self.baseline, objects=value) for value in (-1, True, '23', 23.0))
        for current in mutations:
            with self.subTest(current=current):
                self.assertFalse(compare_shared_resources(self.baseline, current)['nonincreasing'])
                self.assertFalse(compare_shared_resources(current, self.baseline)['nonincreasing'])

    def test_matching_counts_cannot_pass_a_visible_or_unconfirmed_popup(self):
        closed = dict(matched=True, popup_hidden=True,
            resource_comparison=compare_shared_resources(self.baseline, self.baseline))
        self.assertTrue(popup_recovered(closed))
        for bad in (dict(closed, popup_hidden=False), dict(closed, matched=False),
                    dict(closed, resource_comparison={}), {}):
            with self.subTest(recovery=bad): self.assertFalse(popup_recovered(bad))


if __name__ == '__main__': unittest.main()
