#pragma once
#include "global.h"

namespace Stealth {
    void UnlinkFromModuleList(PDRIVER_OBJECT self);
    void ScrubUnloadedDrivers(void);
}
