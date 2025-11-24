#header-only library
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO ridiculousfish/libdivide
    REF eea3b2436925396287abe64298e0e8a1c5674f68
    SHA512 d53d5ec17ac166ae80b7f8f9e83bbc5e9948eba77169cfd5014550d930f01cd52ee2225dcdf5ad9891868a03fa2f2c4fb20990dd3647acb4fd857d97335fe053
    HEAD_REF master
    PATCHES
        "dont-allow-libdivide-to-crash.patch"
)

file(INSTALL
    "${SOURCE_PATH}/libdivide.h"
    DESTINATION "${CURRENT_PACKAGES_DIR}/include"
)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/.github")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/.vscode")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/test")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/doc")

file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE.txt")
