package com.beam.android.ipc;

// UI -> service observer. oneway: state pushes must never block the :vpn process.
oneway interface IBeamStateCallback {
    oneway void onStateChanged(int state, String detail);
}
