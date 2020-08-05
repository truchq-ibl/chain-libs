extern crate cbor_event;
extern crate rustc_serialize;
extern crate serde_json;
extern crate base64;

use cardano::address;
use cardano::wallet::{bip44, keygen};
use cardano::util::{hex};
use cardano::hdwallet::{self, XPrv, XPRV_SIZE};
use cardano::wallet::scheme::{Wallet, SelectionPolicy};
use cardano::bip::bip39::{self, Mnemonics, MnemonicString, dictionary};
use cardano::{config::ProtocolMagic, txutils, tx, coin};
use cardano::util::base58;
use cardano::tx::{txaux_serialize, txaux_serialize_size};
use cardano::fee::{self};
use cardano::util::try_from_slice::TryFromSlice;

use cardano::{
    address::ExtendedAddr
};

use address::ffi_address_to_base58;

use cardano::bip;

use std::{ffi, slice, ptr};
use std::os::raw::{c_char};

use rustc_serialize::base64::{ToBase64};
use base64::{decode};
use serde_json::{Value, Error, error::ErrorCode};

const DEBUG: bool = false;
const FAKE_ROOT_KEY: &str = "0071ea50485d5926f95d2d4b9658c558d418e8879b25d8ecabedd4505acc865aad2506d8e42e7a6ea7979b7b92027e485b4dcd97180743d4fbf90db8b65cf595696863a0f51f744516e0bf8318cb391afc948d69818b14da13c2d5de20e367b7";
type WalletPtr  = *mut bip44::Wallet;

#[no_mangle]
pub extern "C"
fn create_rootkey( mnemonics: *const c_char
                 , password:  *const c_char )
-> *mut c_char
{
    let mnemonics     = unsafe {ffi::CStr::from_ptr(mnemonics)};
    let mnemonics_str = mnemonics.to_str().unwrap();
    let mnemonics     = MnemonicString::new(&dictionary::ENGLISH, mnemonics_str.to_string()).unwrap();

    let password      = unsafe {ffi::CStr::from_ptr(password)};
    let password_str  = password.to_str().unwrap();
    let password      = password_str.as_bytes();

    let seed = bip39::Seed::from_mnemonic_string(&mnemonics, &password);
    let xprv = XPrv::generate_from_bip39(&seed);

    ffi::CString::new(xprv.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C"
fn create_rootkey_from_entropy( mnemonics       : *const c_char
                              , password_ptr    : *const u8
                              , password_size   : usize )
-> *mut c_char
{
    let password = unsafe {slice::from_raw_parts(password_ptr, password_size)};

    let mnemonics = unsafe {ffi::CStr::from_ptr(mnemonics)};
    let mnemonics_str = mnemonics.to_str().unwrap();
    let mnemonics = match Mnemonics::from_string(&dictionary::ENGLISH, mnemonics_str) {
        Err(_) => return ptr::null_mut(),
        Ok(e) => e,
    };

    let entropy = match bip::bip39::Entropy::from_mnemonics(&mnemonics) {
        Err(_) => return ptr::null_mut(),
        Ok(e) => e,
    };

    let mut seed = [0u8; XPRV_SIZE];
    keygen::generate_seed(&entropy, password, &mut seed);
    let xprv = XPrv::normalize_bytes(seed);

    ffi::CString::new(xprv.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C"
fn create_wallet(root_key: *const c_char)
    -> WalletPtr
{
    let root_key = unsafe {
        ffi::CStr::from_ptr(root_key).to_string_lossy()
    };

    let xprv_vec = hex::decode(&root_key).unwrap();
    let mut xprv_bytes = [0; hdwallet::XPRV_SIZE];
    xprv_bytes.copy_from_slice(&xprv_vec[..]);

    let root_xprv  = hdwallet::XPrv::from_bytes_verified(xprv_bytes).unwrap();
    let wallet     = bip44::Wallet::from_root_key(root_xprv, Default::default());
    let wallet_box = Box::new(wallet);

    Box::into_raw(wallet_box)
}

#[no_mangle]
pub extern "C"
fn delete_wallet(wallet_ptr: WalletPtr)
{
    unsafe {
        Box::from_raw(wallet_ptr)
    };
}

#[derive(Debug)]
struct Address {
    wallet  : WalletPtr,
    address : *mut c_char,
    private : *mut c_char,
}

fn cardano_generate_address ( root_key       : *const c_char
                           , account_index  : u32
                           , internal       : u32
                           , from_index     : u32
                           , num_indices    : usize)
    -> Address
{
    let wallet_ptr = create_wallet(root_key);
    let wallet     = unsafe {wallet_ptr.as_mut()}.expect("Not a NULL PTR");

    let account     = wallet.create_account("", account_index);

    let addr_type = if internal == 1 {
        bip44::AddrType::Internal
    } else {
        bip44::AddrType::External
    };

    let mut c_address = ffi::CString::new("");
    let mut c_address_priv = ffi::CString::new("");
    for (idx, xprv) in account.address_generator(addr_type, from_index)
                              .take(1)
                              .enumerate()
    {
      let address = ExtendedAddr::new_simple(*xprv.public(), ProtocolMagic::default().into());
      c_address = Ok(ffi_address_to_base58(&address));
      c_address_priv = ffi::CString::new(xprv.to_string());
      // println!("address index {}: {}: {}: {}", idx, address, *xprv, *xprv.public());
    }

    Address {
        wallet  : wallet_ptr,
        address : c_address.unwrap().into_raw(),
        private : c_address_priv.unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C"
fn generate_address ( root_key       : *const c_char
                    , account_index  : u32
                    , internal       : u32
                    , from_index     : u32
                    , num_indices    : usize)
-> *mut c_char
{
    let result = cardano_generate_address(root_key, account_index, internal, from_index, num_indices);
    delete_wallet(result.wallet);
    result.address
}

#[no_mangle]
pub extern "C"
fn generate_address_private ( root_key       : *const c_char
                    , account_index  : u32
                    , internal       : u32
                    , from_index     : u32
                    , num_indices    : usize)
-> *mut c_char
{
    let result = cardano_generate_address(root_key, account_index, internal, from_index, num_indices);
    delete_wallet(result.wallet);
    result.private
}

#[no_mangle]
pub extern fn validate_address(c_address: *const c_char) -> *mut c_char {
    let address_base58 = unsafe { ffi::CStr::from_ptr(c_address).to_bytes() };
    let result;
    if let Ok(address_raw) = base58::decode_bytes(address_base58) {
        if let Ok(_) = ExtendedAddr::try_from_slice(&address_raw[..]) {
            result = "0";
        } else {
            result = "2";
        }
    } else {
        result = "1";
    }

    ffi::CString::new(result).unwrap().into_raw()
}

#[derive(Debug)]
struct Transaction {
    txaux   : tx::TxAux,
    fee     : fee::Fee,
    txid    : *mut c_char
}

fn cardano_new_transaction  ( root_key  : *const c_char
                            , utxos     : *const c_char
                            , from_addr : *const c_char
                            , to_addrs  : *const c_char )
-> Result<Transaction, Error>
{
    // parse input c_char to string
    let utxos = unsafe { ffi::CStr::from_ptr(utxos) };
    let addrs = unsafe { ffi::CStr::from_ptr(to_addrs) };

    let utxos_str = utxos.to_str().unwrap();
    let addrs_str = addrs.to_str().unwrap();

    // Parse the string of data into json
    let utxos_json: Value = serde_json::from_str(&utxos_str.to_string())?;
    let addrs_json: Value = serde_json::from_str(&addrs_str.to_string())?;

    if !utxos_json.is_array() || !addrs_json.is_array() {
        return Err(Error::syntax(ErrorCode::ExpectedObjectOrArray, 1, 1));
    }

    // get input array length
    let utxos_arr_len = utxos_json.as_array().unwrap().len();
    let addrs_arr_len = addrs_json.as_array().unwrap().len();

    if utxos_arr_len <= 0 || addrs_arr_len <= 0 {
        return Err(Error::syntax(ErrorCode::ExpectedObjectOrArray, 1, 1));
    }

    let wallet_ptr = cardano_generate_address(root_key, 0, 0, 0, 1).wallet;
    let wallet     = unsafe {wallet_ptr.as_mut()}.expect("Not a NULL PTR");

    // init input & output of transaction
    let mut inputs = vec![];
    let mut outputs = vec![];

    // convert from_addr from string to ExtendedAddr
    let from_addr = unsafe {
        ffi::CStr::from_ptr(from_addr).to_string_lossy()
    };

    let from_addr_bytes = base58::decode_bytes(from_addr.as_bytes()).unwrap();
    let from = ExtendedAddr::try_from_slice(&from_addr_bytes[..]).unwrap();

    // init transaction input from utxos
    for x in 0..utxos_arr_len {
        let trx_id = &utxos_json[x]["id"].as_str().unwrap();
        let txin = tx::TxoPointer::new(tx::TxId::try_from_slice(&hex::decode(trx_id).unwrap()).unwrap(), utxos_json[x]["index"].to_string().parse::<u32>().unwrap());

        let addressing = bip44::Addressing::new(0, bip44::AddrType::External, 0).unwrap();
        let txout = tx::TxOut::new(from.clone(), coin::Coin::new(utxos_json[x]["value"].to_string().parse::<u64>().unwrap()).unwrap());

        inputs.push(txutils::Input::new(txin, txout, addressing));
    }

    // init transaction output from to_address
    for x in 0..addrs_arr_len {
        let to_raw = base58::decode_bytes(addrs_json[x]["addr"].as_str().unwrap().as_bytes()).unwrap();
        let to = ExtendedAddr::try_from_slice(&to_raw[..]).unwrap();

        outputs.push(tx::TxOut::new(to.clone(), coin::Coin::new(addrs_json[x]["value"].to_string().parse::<u64>().unwrap()).unwrap()))
    }

    let (txaux, fee) = wallet.new_transaction(
        ProtocolMagic::default(),
        SelectionPolicy::default(),
        inputs.iter(),
        outputs,
        &txutils::OutputPolicy::One(from.clone())).unwrap();

    if DEBUG {
        println!("############## Transaction prepared #############");
        println!("  txaux {}", txaux);
        println!("  tx id {}", txaux.tx.id());
        println!("  from address {}", from);
        println!("  fee: {:?}", fee);
        println!("###################### End ######################");
    }

    let txid = format!("{}", txaux.tx.id());

    delete_wallet(wallet_ptr);
    return Ok(Transaction {
        txaux   : txaux,
        fee     : fee,
        txid    : ffi::CString::new(txid).unwrap().into_raw()
    })
}

#[no_mangle]
pub extern "C"
fn new_transaction( root_key : *const c_char, utxos : *const c_char, from_addr : *const c_char, to_addrs: *const c_char )
-> *mut c_char
{
    let result = cardano_new_transaction(root_key, utxos, from_addr, to_addrs);
    match result {
        Ok(v) => {
            // convert raw transaction to string, base64
            let mut ser = cbor_event::se::Serializer::new_vec();
            txaux_serialize(&v.txaux.tx, &v.txaux.witness, &mut ser).unwrap();
            let cbors = ser.finalize();
            let result = cbors.to_base64(rustc_serialize::base64::STANDARD);
            ffi::CString::new(result).unwrap().into_raw()
        },
        Err(_e) => return ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C"
fn transaction_fee(utxos : *const c_char, from_addr : *const c_char, to_addrs: *const c_char ) -> *mut c_char
{
    let fake_root_key = ffi::CString::new(FAKE_ROOT_KEY).expect("CString::new failed");
    let result = cardano_new_transaction(fake_root_key.as_ptr(), utxos, from_addr, to_addrs);
    match result {
        Ok(v) => {
            let fee = v.fee.to_coin().to_integral().to_string();
            ffi::CString::new(fee).unwrap().into_raw()
        },
        Err(_e) => return ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C"
fn transaction_size(utxos : *const c_char, from_addr : *const c_char, to_addrs: *const c_char ) -> *mut c_char
{
    let fake_root_key = ffi::CString::new(FAKE_ROOT_KEY).expect("CString::new failed");
    let result = cardano_new_transaction(fake_root_key.as_ptr(), utxos, from_addr, to_addrs);
    match result {
        Ok(v) => {
            // convert raw transaction to string, base64
            let size = txaux_serialize_size(&v.txaux.tx, &v.txaux.witness);
            ffi::CString::new(size.to_string()).unwrap().into_raw()
        },
        Err(_e) => return ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C"
fn get_txid( root_key : *const c_char, utxos : *const c_char, from_addr : *const c_char, to_addrs: *const c_char ) -> *mut c_char
{
    let result = cardano_new_transaction(root_key, utxos, from_addr, to_addrs);
    match result {
        Ok(v) => {
            let txid = unsafe { ffi::CStr::from_ptr(v.txid).to_str().unwrap() };
            ffi::CString::new(txid).unwrap().into_raw()
        },
        Err(_e) => return ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C"
fn validate_private_key(root_key: *const c_char)
    -> *mut c_char
{
    let root_key = unsafe {
        ffi::CStr::from_ptr(root_key).to_string_lossy()
    };
    let result;
    let pk_string = &root_key;
    let mut is_hex_digit = true;
    for character in pk_string.to_string().chars() {
        is_hex_digit = is_hex_digit && character.is_ascii_hexdigit();
        if !is_hex_digit {
            break;
        }
    }
    if is_hex_digit {
        let xprv_vec = hex::decode(&root_key).unwrap();
        let mut xprv_bytes = [0; hdwallet::XPRV_SIZE];
        if xprv_vec.len() != hdwallet::XPRV_SIZE {
            result = "1";
        } else {
            xprv_bytes.copy_from_slice(&xprv_vec[..]);
            let is_valid = hdwallet::XPrv::from_bytes_verified(xprv_bytes);
            match is_valid {
                Ok(_v) => {
                    result = "0";
                },
                Err(_e) => {
                    result = "1";
                },
            }
        }
    } else {
        result = "1";
    }

    ffi::CString::new(result).unwrap().into_raw()
}

#[cfg(feature = "jni")]
#[allow(non_snake_case)]
pub mod android {
  extern crate jni;
  use super::*;
  use self::jni::JNIEnv;
  use self::jni::objects::{JClass, JString};
  use self::jni::sys::{jint, jstring };
#[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_createTransaction(
    env: JNIEnv, _: JClass, root_key: JString, utxos: JString, from_addr: JString, to_addrs: JString
  ) -> jstring {
      let transaction = new_transaction(env.get_string(root_key).expect("invalid pattern string").as_ptr(),
      env.get_string(utxos).expect("invalid pattern string").as_ptr(),
      env.get_string(from_addr).expect("invalid pattern string").as_ptr(),
      env.get_string(to_addrs).expect("invalid pattern string").as_ptr(),
      );
      let transaction_ptr = ffi::CString::from_raw(transaction);
      let output = env.new_string(transaction_ptr.to_str().unwrap()).expect("Couldn't create java string!");
      output.into_inner()
  }

  #[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_createAddressFromRootKey(
    env: JNIEnv, _: JClass, rootkey: JString, account_index: jint, internal: jint, from_index: jint, num_indices: jint
  ) -> jstring {
      let address = generate_address(env.get_string(rootkey).expect("invalid pattern string").as_ptr(),
      account_index as u32,
      internal as u32,
      from_index as u32,
      num_indices as usize,
      );
      let address_ptr = ffi::CString::from_raw(address);
      let output = env.new_string(address_ptr.to_str().unwrap()).expect("Couldn't create java string!");
      output.into_inner()
  }

  #[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_createAddressPrivFromRootKey(
    env: JNIEnv, _: JClass, rootkey: JString, account_index: jint, internal: jint, from_index: jint, num_indices: jint
  ) -> jstring {
      let private = generate_address_private(env.get_string(rootkey).expect("invalid pattern string").as_ptr(),
      account_index as u32,
      internal as u32,
      from_index as u32,
      num_indices as usize,
      );
      let private_ptr = ffi::CString::from_raw(private);
      let output = env.new_string(private_ptr.to_str().unwrap()).expect("Couldn't create java string!");
      output.into_inner()
  }

    #[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_createRootKey(
    env: JNIEnv, _: JClass, mnemonics: JString, password: JString
  ) -> jstring {
      let rootkey = create_rootkey(env.get_string(mnemonics).expect("invalid pattern string").as_ptr(), env.get_string(password).expect("invalid pattern string").as_ptr());
      let rootkey_ptr = ffi::CString::from_raw(rootkey);
      let output = env.new_string(rootkey_ptr.to_str().unwrap()).expect("Couldn't create java string!");
      output.into_inner()
  }

  #[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_validateAddress(
    env: JNIEnv, _: JClass, address: JString
  ) -> jstring {
        let result = validate_address(env.get_string(address).expect("invalid pattern string").as_ptr());
        let result_ptr = ffi::CString::from_raw(result);
        let output = env.new_string(result_ptr.to_str().unwrap()).expect("Couldn't create java string!");
        output.into_inner()
  }

    #[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_validatePrivateKey(
    env: JNIEnv, _: JClass, rootKey: JString
  ) -> jstring {
        let result = validate_private_key(env.get_string(rootKey).expect("invalid pattern string").as_ptr());
        let result_ptr = ffi::CString::from_raw(result);
        let output = env.new_string(result_ptr.to_str().unwrap()).expect("Couldn't create java string!");
        output.into_inner()
  }

#[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_transactionFee(
    env: JNIEnv, _: JClass, utxos: JString, from_addr: JString, to_addrs: JString
  ) -> jstring {
      let fee = transaction_fee(env.get_string(utxos).expect("invalid pattern string").as_ptr(),
      env.get_string(from_addr).expect("invalid pattern string").as_ptr(),
      env.get_string(to_addrs).expect("invalid pattern string").as_ptr(),
      );
      let fee_ptr = ffi::CString::from_raw(fee);
      let output = env.new_string(fee_ptr.to_str().unwrap()).expect("Couldn't create java string!");
      output.into_inner()
  }

    #[no_mangle]
    pub unsafe extern fn Java_com_reactlibrary_RNIblCardanoModule_transactionSize(
    env: JNIEnv, _: JClass, utxos: JString, from_addr: JString, to_addrs: JString
  ) -> jstring {
      let size_tx = transaction_size(env.get_string(utxos).expect("invalid pattern string").as_ptr(),
      env.get_string(from_addr).expect("invalid pattern string").as_ptr(),
      env.get_string(to_addrs).expect("invalid pattern string").as_ptr(),
      );
      let size_tx_ptr = ffi::CString::from_raw(size_tx);
      let output = env.new_string(size_tx_ptr.to_str().unwrap()).expect("Couldn't create java string!");
      output.into_inner()
  }

}

#[no_mangle]
pub extern "C"
fn decode_raw( raw : *const c_char)
{
        // let raw = "goOfggDYGFgkglgg6MUQEk27Jp6YYnQSyYp8ZFyT0b0xEnSTOqxhhvhSY2sB/5+CgtgYWEKDWBzUi80URjMCiZ2tTIOD4MGyALnd4HW109rswwqdoQFYHlgcxdlJsC4jIxzHH/ppHenN2yDvmwjmLrLF6FeJLAAaI6X2cho7i4fAgoLYGFghg1gcjSloNa0rJR3Kg3hoH8p8nUva7ctQCzcjSDqu/KAAGqjQ9W0bAAAAA0KDuDD/oIGCANgYWIWCWEDV82rY3Tcl9dMrAOEBGOecgVamwUppCh0DpzNZKO7x+9NK7ywQAb260xRx9qDJ4jXfa6BxBsZHlp8BWEEaOmzZWECsDHPwjKRgJ1ENI8hDjs5E6ps4WoApM1JXrYen+hx8Z54yWFWBf7wo77a/YM+idUd2fVHmdNiJ38lrqJBU6uoH";
    let rawtx = unsafe { ffi::CStr::from_ptr(raw) };
    let raw_str = rawtx.to_str().unwrap();
    let raw_bytes = &decode(raw_str).unwrap()[..];

    let mut raw = cbor_event::de::Deserializer::from(raw_bytes);
    let _txaux : tx::TxAux = cbor_event::de::Deserialize::deserialize(&mut raw).unwrap();

    println!("############## Transaction Decode #############");
    println!("  raw_bytes {}", raw_bytes.len());
    println!("  txaux {}", _txaux);
    println!("  tx id {}", _txaux.tx.id());
    println!("###################### End ######################");
}
