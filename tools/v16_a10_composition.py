"""Fixed strict WRITE/recovery links and advisory legacy matrix scale preflight.

This module does not execute virtual machines or alter legacy admission rules.
Link records must come from the fixed independently replayed native verifiers;
the command-line boundary in verify_v16_a10_composition supplies those records.
"""
from __future__ import annotations

import math
from pathlib import Path

from check_prototype_evidence import require


def validate_links(initial_disk, initial_sha256, cut, recovery, *, same_host_monotonic_session=False):
    """Validate only the fixed seed -> mode3 v2 WRITE -> mode3 v1 recovery."""
    require(same_host_monotonic_session is True, 'explicit caller same-host-monotonic-session acknowledgement required')
    expected_initial = [str(Path(initial_disk).resolve()), str(Path(cut['directory'])/'disk.raw')]
    for record, initial in zip((cut, recovery), expected_initial):
        context, inputs, identity = (record[key] for key in ('context', 'inputs', 'identity'))
        root = str(Path(record['directory']).resolve())
        require(context['capture_root'] == root and context['backing_path'] == root+'/disk.raw',
                'composition actual capture/backing path mismatch')
        require(str(Path(context['initial_source']).resolve()) == initial,
                'composition actual initial source differs from selected ancestor')
        require(inputs['mode'] == 3 and inputs['phase'] == 'before'
                and inputs['reverse_replies'] is False
                and record['summary']['nbd_trace']['reordered_replies'] is False,
                'composition requires nonreordered before mode3')
        require(inputs['initial_disk_sha256'] == identity['initial_sha256'] == initial_sha256,
                'composition initial disk identity mismatch')
        initial_sha256 = record['summary']['nbd_trace']['disk_final_sha256']

    require(cut['context']['version'] == 'a10-write-native-v2'
            and type(cut['inputs']['cut']) is int and cut['inputs']['cut'] > 0
            and cut['summary']['status'] == 'NOT_RUN'
            and cut['summary']['cut_observed'] is True
            and cut['summary']['native_write_cut_custody_verified'] is True,
            'composition requires strict v2 WRITE cut')
    require(recovery['context']['version'] == 'a10-native-v1'
            and type(recovery['inputs']['cut']) is int and recovery['inputs']['cut'] == 0
            and recovery['summary']['status'] == 'PASS'
            and recovery['summary']['cut_observed'] is False
            and recovery['summary']['native_mode_verified'] is True,
            'composition requires original v1 clean recovery completion')
    for key in ('source_sha256', 'build_sha256', 'image_sha256', 'qemu'):
        require(cut['identity'][key] == recovery['identity'][key],
                'composition source/build/image/QEMU mismatch: '+key)
    require(cut['binding']['uuid'] == recovery['binding']['uuid'], 'composition filesystem UUID mismatch')
    require(cut['nonce'] != recovery['nonce'], 'composition reused nonce')
    for key in ('backend_run_id', 'backing_path'):
        require(cut['context'][key] != recovery['context'][key], 'composition reused '+key)
    parent_endpoints = set(cut['context']['endpoints'].values())
    child_endpoints = set(recovery['context']['endpoints'].values())
    require(parent_endpoints.isdisjoint(child_endpoints), 'composition reused backend endpoint')
    parent_times = [cut['lifecycle'][name]['monotonic_ns'] for name in ('final-disk','identity-after')]
    child_times = [recovery['lifecycle'][name]['monotonic_ns']
                   for name in ('identity-before','backend-open','spawn')]
    require(all(type(t) is int and t > 0 for t in parent_times+child_times)
            and max(parent_times) < min(child_times), 'composition parent/child chronology inversion')
    return dict(selected_chain_verified=True, formal_A10_status='NOT_RUN', A10_complete=False,
                native_filesystem_fault_matrix_complete=False, mandatory_matrix_slots_closed=0,
                native_acceptance_status='NOT_RUN', external_seed_native_custody_claimed=False,
                chronology_trust='caller-asserted-same-host-monotonic-session',
                scope='one caller-selected strict nonreordered WRITE cut and chronological recovery')


def _nonnegative_integer(value, name):
    require(type(value) is int and value >= 0, 'invalid '+name)
    return value


def _costs(value, allowed, name):
    require(type(value) is dict and value.keys() <= allowed, 'invalid '+name+' keys')
    for key, number in value.items():
        require(type(number) in (int, float) and math.isfinite(number) and number >= 0,
                'invalid '+name+' '+key)
    return value


def legacy_preflight(overwrite_count, recovery_point_counts, *, assumed_recovery_count,
                     observed_costs, resource_budget):
    """Count legacy children, distinguishing measured branches from assumptions.

    Counts are in overwrite-prefix order (4 per overwrite point); missing trailing
    branches or None entries remain unknown. Costs are explicit observed per-child
    seconds/bytes. Caps are advisory here: the existing legacy CLI is untouched.
    """
    prefixes = 4 * _nonnegative_integer(overwrite_count, 'overwrite_count')
    require(type(recovery_point_counts) is list and len(recovery_point_counts) <= prefixes,
            'invalid recovery_point_counts')
    measured = [count for count in recovery_point_counts if count is not None]
    for count in measured:
        _nonnegative_integer(count, 'recovery branch count')
    if assumed_recovery_count is not None:
        _nonnegative_integer(assumed_recovery_count, 'assumed_recovery_count')
    costs = _costs(observed_costs, {'seconds_per_child','bytes_per_child'}, 'observed_costs')
    budget = _costs(resource_budget,
                    {'max_children','max_runtime_seconds','max_storage_bytes'}, 'resource_budget')
    unknown = prefixes - len(measured)
    measured_sum = sum(measured)
    base = 3 + 2 * prefixes
    minimum = base + 8 * measured_sum
    exact = minimum if not unknown else None
    conditional = (base + 8 * (measured_sum + unknown * assumed_recovery_count)
                   if unknown and assumed_recovery_count is not None else None)
    estimate = exact if exact is not None else conditional
    runtime = estimate * costs['seconds_per_child'] if estimate is not None and 'seconds_per_child' in costs else None
    storage = estimate * costs['bytes_per_child'] if estimate is not None and 'bytes_per_child' in costs else None
    cap_count = estimate if estimate is not None else minimum
    values = {'max_children': cap_count,
              'max_runtime_seconds': cap_count * costs['seconds_per_child'] if 'seconds_per_child' in costs else None,
              'max_storage_bytes': cap_count * costs['bytes_per_child'] if 'bytes_per_child' in costs else None}
    exceeded = [key for key, cap in budget.items() if values[key] is not None and values[key] > cap]
    missing_costs = runtime is None or storage is None
    if exceeded:
        status = 'REFUSED_RESOURCE_BUDGET'
    elif unknown:
        status = 'INDETERMINATE_UNMEASURED_BRANCHES'
    elif missing_costs:
        status = 'INDETERMINATE_UNMEASURED_COSTS'
    else:
        status = 'ESTIMATE_WITHIN_BUDGET'
    return dict(status=status, overwrite_count=overwrite_count, overwrite_prefix_count=prefixes,
                measured_branch_count=len(measured), unknown_branch_count=unknown,
                measured_recovery_point_sum=measured_sum, assumed_recovery_count=assumed_recovery_count,
                minimum_child_count=minimum, exact_child_count=exact, conditional_child_count=conditional,
                estimate_kind='exact' if exact is not None else 'conditional' if conditional is not None else 'unknown',
                runtime_seconds=runtime, storage_bytes=storage, observed_costs=dict(costs),
                resource_budget=dict(budget), exceeded_caps=exceeded,
                budget_approved=False, execution_authorized=False, legacy_cli_intercepted=False,
                VM_runs=0, formal_A10_status='NOT_RUN', A10_complete=False, mandatory_matrix_slots_closed=0)
