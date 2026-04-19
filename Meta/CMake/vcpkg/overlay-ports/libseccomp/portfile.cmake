# FIX-BEFORE-PR: Just contribute this to upstream vcpkg once I know it's working

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO seccomp/libseccomp
    REF v2.6.0
    SHA512 ccacc8da8d865998b14f1221d1acc0e7bf5038f06a10a2aec976330aedcb64b075f085b3f39d3dddce3adcb71d125463cadc45fb6908ddffae3d002bb135d096
    HEAD_REF v2.6.0
)

# gperf is needed for installation to succeed
set(GPERF_EXECUTABLE "${CURRENT_HOST_INSTALLED_DIR}/tools/gperf/gperf")

vcpkg_configure_make(
    SOURCE_PATH "${SOURCE_PATH}"
    AUTOCONFIG
    OPTIONS
        GPERF="${GPERF_EXECUTABLE}"
)

vcpkg_install_make()

vcpkg_fixup_pkgconfig()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/share")
