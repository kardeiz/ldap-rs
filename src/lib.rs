#![allow(dead_code, non_upper_case_globals, non_snake_case, non_camel_case_types)]

mod ffi;

use std::ffi::{CString, CStr};
use std::error::Error;
use std::convert::From;
use std::collections::HashMap;

use std::os::raw;

pub static LDAP_SUCCESS: i32 = 0x00;
pub static LDAP_OPT_PROTOCOL_VERSION: i32 = 0x0011;

pub type LocalResult<T> = Result<T, Box<Error+Send+Sync>>;

#[derive(Debug)]
pub struct Conn {
  pub ptr: *mut ffi::LDAP
}

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe { ffi::ldap_destroy(self.ptr); }
    }
}

impl Conn {

    pub fn new() -> Self {
        Conn { ptr: ::std::ptr::null_mut() }
    }

    pub fn connect(&mut self, url: &str) -> LocalResult<()> {
        let url = try!(CString::new(url));
        let res = unsafe { ffi::ldap_initialize(&mut self.ptr, url.as_ptr()) };
        
        Self::decode(res)
    }

    pub fn set(&mut self, key: i32, val: i32) -> LocalResult<()> {
        let res = unsafe {
            let key = key as raw::c_int;
            let val = &val as *const _ as *const raw::c_void;
            ffi::ldap_set_option(self.ptr, key, val)
        };
        Self::decode(res)
    }

    pub fn bind(&mut self, dn: &str, passwd: &str) -> LocalResult<()> {
        let dn_as_c = try!(CString::new(dn));
        let passwd_as_c = try!(CString::new(passwd));

        let mechanism = ::std::ptr::null_mut();

        let mut credentials = ffi::BerValue {
            bv_len: passwd.len() as ffi::ber_len_t,
            bv_val: passwd_as_c.as_ptr() as *mut raw::c_char
        };

        let mut serverctrls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let mut clientctrls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let mut servercredp: *mut ffi::BerValue = ::std::ptr::null_mut();

        let res = unsafe {
            ffi::ldap_sasl_bind_s(
                self.ptr, 
                dn_as_c.as_ptr(), 
                mechanism,
                &mut credentials,
                &mut serverctrls,
                &mut clientctrls,
                &mut servercredp)
        };
        Self::decode(res)
    }

    pub fn search(&self, 
        base: &str, 
        scope: isize, 
        filter: &str) -> LocalResult<Message> {
    
        let base = try!(CString::new(base));
        let filter = try!(CString::new(filter));

        let mut msg: *mut ffi::LDAPMessage = ::std::ptr::null_mut();
        let mut serverctrls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let mut clientctrls: *mut ffi::LDAPControl = ::std::ptr::null_mut();
        let timeout: *mut ffi::Struct_timeval = ::std::ptr::null_mut();
    
        let res = unsafe {
            ffi::ldap_search_ext_s(
                self.ptr, 
                base.as_ptr(), 
                scope as raw::c_int, 
                filter.as_ptr(), 
                ::std::ptr::null_mut() as *mut *mut raw::c_char, 
                0, 
                &mut serverctrls, 
                &mut clientctrls, 
                timeout, 
                0, 
                &mut msg)
        };
        Self::decode(res)
            .map(|_| Message { ptr: msg, destroyable: true } )

    }

    fn decode(res: i32)  -> LocalResult<()> {
        if res == LDAP_SUCCESS {
            Ok(())
        } else {
            let out: String = unsafe {
                let x = ffi::ldap_err2string(res as raw::c_int);
                CStr::from_ptr(x).to_str().ok()
                    .map(|x| x.into() )
                    .unwrap_or("Unknown exception".into())
            };
            Err(out.into())
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub ptr: *mut ffi::LDAPMessage,
    pub destroyable: bool
}

impl Drop for Message {
    fn drop(&mut self) {
        if self.destroyable {
            unsafe { ffi::ldap_msgfree(self.ptr); }
        }        
    }
}

pub struct EntriesIterator<'a> {
    pub curr: Option<Message>,
    pub conn: &'a Conn
}

impl<'a> Iterator for EntriesIterator<'a> {
    type Item = Message;

    fn next(&mut self) -> Option<Self::Item> {
        let curr = self.curr.take();
        self.curr = curr.as_ref().and_then(|x| x.next_entry(self.conn));
        curr
    }
}

impl Message {

    pub fn entries<'b>(&self, conn: &'b Conn) -> EntriesIterator<'b> {
        EntriesIterator { curr: self.first_entry(conn), conn: conn }
    }

    pub fn first_entry(&self, conn: &Conn) -> Option<Message> {
        let res = unsafe { ffi::ldap_first_entry(conn.ptr, self.ptr) };
        if res.is_null() { 
            None
        } else {
            Some(Message { ptr: res, destroyable: false })
        }   
    }
    pub fn next_entry(&self, conn: &Conn) -> Option<Message> {
        let res = unsafe { ffi::ldap_next_entry(conn.ptr, self.ptr) };        
        if res.is_null() { 
            None
        } else {
            Some(Message { ptr: res, destroyable: false })
        }
    }

    pub fn get_dn(&self, conn: &Conn) -> Option<String> {
        unsafe { 
            let res = ffi::ldap_get_dn(conn.ptr, self.ptr);
            CStr::from_ptr(res).to_str().ok().map(String::from)
        }
    }

    pub fn get_values(&self, conn: &Conn, target: &str) -> Vec<String> {

        let mut out: Vec<String> = Vec::new();

        let target = match CString::new(target) {
            Ok(s) => { s },
            _ => { return out; }
        };    
    
        unsafe {
            let raw_vals = ffi::ldap_get_values_len(
                conn.ptr, 
                self.ptr, 
                target.as_ptr());
            let vals = ::std::slice::from_raw_parts(
                raw_vals, 
                ffi::ldap_count_values_len(raw_vals) as usize);

            for &raw_val in vals {
                let val: &[u8] = ::std::slice::from_raw_parts(
                    (*raw_val).bv_val as *const u8, 
                    (*raw_val).bv_len as usize);
                for v in ::std::str::from_utf8(val).map(String::from) {
                    out.push(v)
                }
            }
        }
        out
    }
}

pub struct Util {
    pub url: String,
    pub bind_dn: String,
    pub bind_passwd: String,
    pub base: String
}

impl Util {

    pub fn conn(&self) -> LocalResult<Conn> {
        let mut conn = Conn::new();
        try!(conn.connect(&self.url));
        try!(conn.set(LDAP_OPT_PROTOCOL_VERSION, 3));
        try!(conn.bind(&self.bind_dn, &self.bind_passwd));
        Ok(conn)
    }

    pub fn search(&self, conn: &Conn, filter: &str, fields: &[&str]) 
        -> Vec<HashMap<String, Vec<String>>> {
        let mut out = Vec::new();
        let res = conn.search(&self.base, 2, filter);
        for e in res.iter().flat_map(|x| x.entries(conn) ) {
            let mut map = HashMap::new();
            for &field in fields {
                let val = e.get_values(conn, field);
                map.insert(field.into(), val);
            }
            out.push(map);
        }
        out
    }

    pub fn authenticate(&self, dn: &str, passwd: &str) -> bool {
        let mut conn = Conn::new();
        if conn.connect(&self.url).is_err() { return false; }
        if conn.set(LDAP_OPT_PROTOCOL_VERSION, 3).is_err() { return false; }
        if conn.bind(dn, passwd).is_err() { return false; }
        true
    }

    pub fn find_and_authenticate(&self,
        conn: &Conn,
        filter: &str,
        fields: &[&str],
        passwd: &str) -> LocalResult<HashMap<String, Vec<String>>> {

        let mut f2 = vec!["distinguishedName"];
        f2.extend_from_slice(fields);

        let mut results = self.search(conn, filter, &f2);

        if results.len() != 1 { return Err("Incorrect results set".into()); }

        let result = results.pop().unwrap();

        let mut authenticated = false;

        if let Some(dn) = (&result).get("distinguishedName")
            .and_then(|x| x.first() ) {
            authenticated = self.authenticate(dn, passwd);
        };

        if authenticated {
            Ok(result)
        } else {
            Err("Could not authenticate".into())
        }

    }

}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {

        let util = Util {
            url: ::std::env::var("LDAP_URL").unwrap(),
            bind_dn: ::std::env::var("BIND_DN").unwrap(),
            bind_passwd: ::std::env::var("BIND_PASSWD").unwrap(),
            base: ::std::env::var("SEARCH_BASE").unwrap()
        };

        let conn = util.conn().expect("NO CONNECTION");

        let results = util.search(&conn, "(cn=jhbrown)", &["mail", "distinguishedName"]);

        println!("{:?}", &results);

        println!("{:?}", util.authenticate(
            &::std::env::var("DN").unwrap(),
            &::std::env::var("PASSWD").unwrap()));

        println!("{:?}", util.find_and_authenticate(
            &conn, 
            "(cn=jhbrown)",
            &["mail", "givenname"],
            &::std::env::var("PASSWD").unwrap()));

        println!("{:?}", util.find_and_authenticate(
            &conn, 
            "&(givenname=Jacob)(sn=Brown))",
            &["mail", "givenname"],
            "foo"));


    }
}
