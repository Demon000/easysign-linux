mod agent;
mod backend;

use native_pkcs11::{CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_OK, FUNC_LIST};

const CKR_ARGUMENTS_BAD: CK_RV = 7;

/// PKCS#11 entry point. NSS looks this up by name; every other function is reached
/// through the returned table. We register our backend here (the framework omits its
/// own C_GetFunctionList because of the `custom-function-list` feature).
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if pp.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    native_pkcs11_traits::register_backend(Box::new(backend::EasySignBackend));
    unsafe {
        *pp = std::ptr::addr_of_mut!(FUNC_LIST);
    }
    CKR_OK
}
