import test from 'node:test';
import assert from 'node:assert/strict';
import {filterWorkspaceItems, shouldPollWorkspace, stateTone, shortKiz} from '../src/workflow.ts';

function item(overrides = {}) {
  return {
    event_id: 'e1',
    kiz: '0102900897077810215Pph%ybnsRtdA',
    operation: 'SALE',
    operation_label: 'Продажа',
    chz_status: 'В обороте',
    decision: 'READY_TO_WITHDRAW',
    decision_label: 'Готово к выводу',
    action_label: 'Вывести из оборота',
    result_label: 'Готово',
    ui_state: 'READY',
    state_label: 'Готово к обработке',
    filter_group: 'READY',
    ready_for_bulk: true,
    reason: 'SALE_IN_CIRCULATION',
    error: null,
    attention_title: null,
    attention_detail: null,
    user_action: null,
    checked_at: null,
    write_operation_id: null,
    write_state: null,
    document_id: null,
    details: {task_number:'1', sticker:'2', receipt_number:'3', fiscal_drive_number:'4', occurred_at:null, amount:'100.00', currency:'RUB', reason_code:null},
    ...overrides,
  };
}

test('filters use backend-provided groups and never infer eligibility', () => {
  const rows = [
    item(),
    item({event_id:'e2', filter_group:'ATTENTION', decision:'MANUAL_REVIEW', ready_for_bulk:false}),
    item({event_id:'e3', filter_group:'ERROR', decision:'ERROR', ready_for_bulk:false}),
    item({event_id:'e4', filter_group:'DONE', decision:'ALREADY_DONE', ready_for_bulk:false}),
    item({event_id:'e5', filter_group:'PROCESSING', ui_state:'WAITING_AGENT', ready_for_bulk:false}),
  ];
  assert.deepEqual(filterWorkspaceItems(rows, 'READY', '').map(x => x.event_id), ['e1']);
  assert.deepEqual(filterWorkspaceItems(rows, 'ATTENTION', '').map(x => x.event_id), ['e2']);
  assert.deepEqual(filterWorkspaceItems(rows, 'ERROR', '').map(x => x.event_id), ['e3']);
  assert.deepEqual(filterWorkspaceItems(rows, 'DONE', '').map(x => x.event_id), ['e4']);
  assert.deepEqual(filterWorkspaceItems(rows, 'PROCESSING', '').map(x => x.event_id), ['e5']);
});

test('search only narrows visible CIS rows', () => {
  const rows = [item(), item({event_id:'e2', kiz:'0102900897078091215s<ESP8kc)NQB'})];
  assert.deepEqual(filterWorkspaceItems(rows, 'ALL', '809121').map(x => x.event_id), ['e2']);
});

test('polling is driven only by backend progress state', () => {
  assert.equal(shouldPollWorkspace([item()]), false);
  assert.equal(shouldPollWorkspace([item({ui_state:'CHECKING'})]), true);
  assert.equal(shouldPollWorkspace([item({ui_state:'WAITING_AGENT'})]), true);
  assert.equal(shouldPollWorkspace([item({ui_state:'VERIFYING'})]), true);
  assert.equal(shouldPollWorkspace([item({ui_state:'COMPLETED', filter_group:'DONE'})]), false);
});

test('visual tone follows backend filter group', () => {
  assert.equal(stateTone(item()), 'good');
  assert.equal(stateTone(item({filter_group:'ATTENTION'})), 'warn');
  assert.equal(stateTone(item({filter_group:'ERROR'})), 'danger');
  assert.equal(stateTone(item({filter_group:'PROCESSING'})), 'progress');
});

test('long CIS is shortened only for display', () => {
  const value = 'x'.repeat(70);
  const display = shortKiz(value);
  assert.equal(display.length < value.length, true);
  assert.equal(display.startsWith('x'.repeat(24)), true);
  assert.equal(display.endsWith('x'.repeat(10)), true);
});
