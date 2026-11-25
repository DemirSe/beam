package com.beam.android.ipc;

import com.beam.android.ipc.IBeamStateCallback;

interface IBeamVpnService {
    void connect(String profileId);
    void disconnect();
    int getState();
    String getStateDetail();
    String getActiveProfileId();
    String getTelemetryJson();
    void registerCallback(IBeamStateCallback callback);
    void unregisterCallback(IBeamStateCallback callback);
}
