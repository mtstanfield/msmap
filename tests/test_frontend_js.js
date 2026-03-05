'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadFiltersModule() {
    const sourcePath = path.join(__dirname, '..', 'web', 'filters.js');
    const source = fs.readFileSync(sourcePath, 'utf8');

    const context = {
        console,
        URLSearchParams,
        window: { msmapDeps: {} },
        DEFAULT_FILTERS: {
            time: '900',
            proto: '',
            ip: '',
            port: '',
            asn: '',
            threat: '',
        },
        filterState: {
            appliedTextFilters: { ip: '', port: '', asn: '' },
            textApplyTimer: null,
            activeFilterPanelTab: 'filters',
            activeThreat: '',
            activeMotion: 'on',
        },
    };

    vm.createContext(context);
    vm.runInContext(source, context, { filename: sourcePath });
    return context.window.msmapDeps;
}

function run() {
    const {
        validateIpValue,
        validatePortValue,
        validateAsnValue,
    } = loadFiltersModule();

    assert.equal(validateIpValue('192.0.2.14').valid, true);
    assert.equal(validateIpValue('192.0.2.14').normalized, '192.0.2.14');
    assert.equal(validateIpValue('2001:db8::1').valid, true);
    assert.equal(validateIpValue('300.0.0.1').valid, false);

    assert.equal(validatePortValue('443').valid, true);
    assert.equal(validatePortValue('443').normalized, '443');
    assert.equal(validatePortValue('0').valid, false);
    assert.equal(validatePortValue('65536').valid, false);
    assert.equal(validatePortValue('abc').valid, false);

    assert.equal(validateAsnValue('AS15169 GOOGLE').valid, true);
    assert.equal(validateAsnValue('google').valid, true);
    assert.equal(validateAsnValue('as').valid, false);
    assert.equal(validateAsnValue('amazon%').valid, false);
    assert.equal(validateAsnValue('aws_').valid, true);

    console.log('frontend_js_validators: ok');
}

run();
