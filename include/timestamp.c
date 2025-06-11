#include <nfp.h>
#include <nfp/me.h>

__intrinsic uint64_t read_timestamp() {
    return __timestamp(); // Reads the current ME clock cycle count
}
