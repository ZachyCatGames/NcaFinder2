#pragma once
#include "LocationRecord.h"

class ISectionProcessor {
public:
    virtual ~ISectionProcessor() = default;

    virtual bool Process(RecoveredList* pRecoveredList, u64 recoveryStartOffset) = 0;
}; // class ISectionProcessor
