use core::panic;
use std::fmt::Debug;
use std::net::{AddrParseError, IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{alphabet, engine, Engine as _};
use hmac::{Hmac, Mac};
use md5::Md5;
use regex::Regex;
use ring::digest;
use serde::{Deserialize, Serialize};

// const USER_AGENT = HashMap::new();
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum LntuCampus {
    HuLuDao = 4,
    FuXin = 1,
}

#[derive(Deserialize, Serialize, Debug)]
struct Info {
    pub username: String,
    pub password: String,
    pub ip: String,
    pub acid: String,
    pub enc_ver: String,
}

fn x_encode(code: &str, key: &str) -> Vec<u8> {
    if code.is_empty() {
        return Vec::new();
    }
    let mut k = x_encode_s(key, false);
    let mut v = x_encode_s(code, true);
    if k.len() < 4 {
        k.append(&mut vec![0; 4 - k.len()]); // TODO: In js, i will return undefine, but here i push 0 into array
    }
    let n = v.len() - 1;
    let mut z: u32 = v[n];
    let mut y: u32 = v[0];
    let c: u32 = 0x86014019 | 0x183639A0;
    let mut m: u32 = 0;
    let mut e: u32 = 0;
    let mut q: u32 = (6. + 52 as f64 / (n + 1) as f64).floor() as u32;
    let mut d: u32 = 0;
    while q > 0 {
        d = d.wrapping_add(c & (0x8CE0D9BF | 0x731F2640));
        e = d >> 2 & 3;
        for p in 0..n {
            y = v[(p + 1) as usize];
            m = z >> 5 ^ y << 2;
            m = m.wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y));
            m = m.wrapping_add(k[((p as u32 & 3) ^ e) as usize] ^ z);
            v[p] = v[p].wrapping_add(m & (0xEFB8D130 | 0x10472ECF));
            z = v[p];
        }
        y = v[0];
        m = z >> 5 ^ y << 2;
        m = m.wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y));
        m = m.wrapping_add(k[((n as u32 & 3) ^ e) as usize] ^ z);
        v[n] = v[n].wrapping_add(m & (0xBB390742 | 0x44C6F8BD));
        z = v[n];
        q -= 1;
    }
    match x_encode_l(&v, false) {
        Ok(s) => s,
        Err(()) => unreachable!(),
    }
}

fn x_encode_s(code: &str, flag: bool) -> Vec<u32> {
    let c = code.len();
    let mut v: Vec<u32> = Vec::with_capacity((c as f64 / 4.0).ceil() as usize);
    code.chars().enumerate().for_each(|(index, u)| {
        if index % 4 == 0 {
            v.push(0);
        }
        let mut encode: [u16; 1] = [0];
        u.encode_utf16(&mut encode);
        *v.last_mut().unwrap() = v.last().unwrap() | (encode[0] as u32) << ((index % 4) as u32 * 8);
    });
    if flag {
        v.push(c as u32);
    }
    v
}

fn x_encode_l(code: &Vec<u32>, flag: bool) -> Result<Vec<u8>, ()> {
    let len = code.len();
    let mut len_2 = (code.len() - 1) << 2;
    if flag {
        let m = code.last().unwrap().clone();
        if (m as i64) < (len_2 as i64) - 3 || m as usize > len_2 {
            return Err(());
        }
        len_2 = m as usize;
    }
    let mut s: Vec<u8> = Vec::with_capacity(len * 4);
    code.iter().for_each(|c| {
        s.push((c.clone() & 0xff) as u8);
        s.push(((c.clone() >> 8) & 0xff) as u8);
        s.push(((c.clone() >> 16) & 0xff) as u8);
        s.push(((c.clone() >> 24) & 0xff) as u8);
    });
    if flag {
        s.truncate(len_2);
    }

    Ok(s)
}

fn encode_info(info: &Info, token: &str) -> String {
    let alphabet =
        alphabet::Alphabet::new("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA")
            .unwrap();
    let config = engine::GeneralPurposeConfig::new().with_encode_padding(true);
    let base64_engine = engine::GeneralPurpose::new(&alphabet, config);
    let text = serde_json::to_string(info).unwrap();
    format!("{{SRBX1}}{}", base64_engine.encode(x_encode(&text, token)))
}

fn get_challenge(username: &str, ip: &IpAddr) -> Result<String, CampusNetworkError> {
    let err_regex = Regex::new("\"error\":\"((\\w)*)\"").unwrap();
    let token_regex = Regex::new("\"challenge\":\"((\\w)*)\"").unwrap();

    let ip = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_string(),
    };

    let url = format!(
        "http://10.11.22.1/cgi-bin/get_challenge?callback=+&username={}&ip={}&_={}",
        username,
        ip,
        get_time()
    );

    let callback = match reqwest::blocking::get(url) {
        Ok(res) => match res.text() {
            Ok(txt) => txt,
            Err(e) => return Err(CampusNetworkError::Others(e.to_string())),
        },
        Err(e) => return Err(CampusNetworkError::DisConnect(e)),
    };

    if let Some(token) = token_regex.captures(&callback) {
        Ok(token[1].to_string())
    } else {
        match err_regex.captures(&callback) {
            Some(e) => Err(CampusNetworkError::Others(e[1].to_string())),
            None => Err(CampusNetworkError::Others(format!(
                "未捕获，原信息为:{}",
                &callback
            ))),
        }
    }
}

fn get_time() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}

fn read_user_info() -> Result<String, CampusNetworkError> {
    let url = reqwest::Url::parse_with_params(
        "http://10.11.22.1/cgi-bin/rad_user_info",
        &[("callback", " "), ("_", &get_time())],
    )
    .unwrap();

    let callback = match reqwest::blocking::get(url) {
        Ok(res) => match res.text() {
            Ok(txt) => txt,
            Err(e) => return Err(CampusNetworkError::Others(e.to_string())),
        },
        Err(e) => return Err(CampusNetworkError::DisConnect(e)),
    };

    Ok(callback)
}

fn login(
    campus: LntuCampus,
    username: &str,
    password: &str,
    ip: IpAddr,
) -> Result<(), CampusNetworkError> {
    let token = match get_challenge(username, &ip) {
        Ok(token) => token,
        Err(e) => return Err(e),
    };
    let ip = ip.to_string();
    let info = Info {
        username: username.to_string(),
        password: password.to_string(),
        ip: ip,
        acid: (campus as u8).to_string(),
        enc_ver: "srun_bx1".to_string(),
    };

    let i = encode_info(&info, &token);

    type HmacMd5 = Hmac<Md5>;
    let mut mac = HmacMd5::new_from_slice(token.as_bytes()).unwrap();
    mac.update(password.as_bytes());
    let hmd5 = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|c| format!("{:02x}", c))
        .collect::<String>();

    let mut chkstr: String = String::new();
    chkstr.push_str(&format!("{}{}", token, username));
    chkstr.push_str(&format!("{}{}", token, &hmd5));
    chkstr.push_str(&format!("{}{}", token, info.acid));
    chkstr.push_str(&format!("{}{}", token, info.ip));
    chkstr.push_str(&format!("{}{}", token, 200)); // n = 200
    chkstr.push_str(&format!("{}{}", token, 1)); //type = 1
    chkstr.push_str(&format!("{}{}", token, i));

    // 一定要使用他的构造方法，因为URL中有特殊字符需要额外处理
    let url = reqwest::Url::parse_with_params(
        "http://10.11.22.1/cgi-bin/srun_portal",
        &[
            ("callback", " "),
            ("action", "login"),
            ("username", username),
            ("password", &format!("{}{}", "{MD5}", &hmd5)),
            ("ac_id", &info.acid),
            ("ip", &info.ip),
            (
                "chksum",
                &digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, chkstr.as_bytes())
                    .as_ref()
                    .iter()
                    .map(|u| format!("{:02x}", u))
                    .collect::<String>(),
            ),
            ("info", &i),
            ("n", "200"),
            ("type", "1"),
            ("os", "Linux"),
            ("name", "Linux"),
            ("double_stack", "0"),
            ("_", &get_time()),
        ],
    )
    .unwrap();

    let result = match reqwest::blocking::get(url) {
        Ok(res) => res,
        Err(e) => return Err(CampusNetworkError::DisConnect(e)),
    };

    let err_regex = Regex::new("\"error\":\"((\\w)*)\"").unwrap();
    let text = match result.text() {
        Ok(text) => text,
        Err(e) => return Err(CampusNetworkError::Others(e.to_string())),
    };
    let reg_result = err_regex.captures(&text);
    match reg_result {
        None => return Err(CampusNetworkError::Others(text)),
        Some(words) => match &words[1] {
            "ok" => Ok(()),
            "SignError" => Err(CampusNetworkError::SignErr),
            "login_error" => Err(CampusNetworkError::PassWordErr),
            _ => Err(CampusNetworkError::Others(words[1].to_string())),
        },
    }
}

pub struct Lntu {}
pub struct LntuHuLuDao {}
pub struct LntuFuXin {}

impl CampusNetwork for Lntu {
    type Campus = LntuCampus;
    fn login(account: &LoginAccount, campus: &LntuCampus) -> Result<(), CampusNetworkError> {
        match campus {
            LntuCampus::HuLuDao => LntuHuLuDao::login(account),
            LntuCampus::FuXin => LntuFuXin::login(account),
        }
    }
    fn logout(account: &LoginAccount, campus: &LntuCampus) -> bool {
        todo!()
    }

    fn get_ip(campus: &LntuCampus) -> Result<IpAddr, CampusNetworkError> {
        match campus {
            LntuCampus::HuLuDao => LntuHuLuDao::get_ip(),
            LntuCampus::FuXin => LntuHuLuDao::get_ip(),
        }
    }
}

use super::{CampusNetwork, CampusNetworkCampus, CampusNetworkError, LoginAccount};
impl CampusNetworkCampus for LntuHuLuDao {
    fn login(account: &LoginAccount) -> Result<(), CampusNetworkError> {
        super::lntu::login(
            LntuCampus::HuLuDao,
            &account.username,
            &account.password,
            account.ip,
        )
    }
    fn logout(account: &LoginAccount) -> bool {
        todo!()
    }
    fn get_ip() -> Result<IpAddr, CampusNetworkError> {
        let info = read_user_info()?;
        let err_regex = Regex::new("\"error\":\"((\\w)*)\"").unwrap();
        let ip_regex = Regex::new("\"online_ip\":\"((([0-9])|([.]))+)\"").unwrap();
        match ip_regex.captures(&info) {
            Some(ip) => match ip[1].parse() {
                Ok(ip) => return Ok(ip),
                Err(e) => return Err(CampusNetworkError::Others(e.to_string())),
            },

            None => Err(CampusNetworkError::Others(info)),
        }
    }
}

impl CampusNetworkCampus for LntuFuXin {
    fn login(account: &LoginAccount) -> Result<(), CampusNetworkError> {
        super::lntu::login(
            LntuCampus::FuXin,
            &account.username,
            &account.password,
            account.ip,
        )
    }
    fn logout(account: &LoginAccount) -> bool {
        todo!()
    }
    fn get_ip() -> Result<IpAddr, CampusNetworkError> {
        let info = read_user_info()?;
        let err_regex = Regex::new("\"error\":\"((\\w)*)\"").unwrap();
        let ip_regex = Regex::new("\"online_ip\":\"((([0-9])|([.]))+)\"").unwrap();
        match ip_regex.captures(&info) {
            Some(ip) => match ip[1].parse() {
                Ok(ip) => return Ok(ip),
                Err(e) => return Err(CampusNetworkError::Others(e.to_string())),
            },

            None => Err(CampusNetworkError::Others(info)),
        }
    }
}
