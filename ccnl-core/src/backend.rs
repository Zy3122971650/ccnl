pub mod lntu;

use std::{io, net::IpAddr};
use thiserror::Error;

pub struct LoginAccount {
    username: String,
    password: String,
    ip: IpAddr,
}

#[derive(Error, Debug)]
pub enum CampusNetworkError {
    #[error("检查你是否连接到网络或者连接到校园网, detils:{0}")]
    DisConnect(#[from] reqwest::Error), // 适用于无法访问认证页面
    #[error("签名错误")]
    SignErr, // 适用于服务器返回校验错误，这意味着你实现的加密算法可能存在问题，这种情况可以多登陆几遍
    #[error("用户名或密码错误")]
    PassWordErr, // 用户名或者密码错误
    #[error("其他错误:{0}")]
    Others(String), // 学校服务器抽风或者各种其他错误，打印出来即可
}

pub trait CampusNetworkCampus {
    fn login(account: &LoginAccount) -> Result<(), CampusNetworkError>;

    fn logout(account: &LoginAccount) -> bool;

    fn get_ip() -> Result<IpAddr, CampusNetworkError>;
}

pub trait CampusNetwork {
    type Campus;
    fn login(account: &LoginAccount, campus: &Self::Campus) -> Result<(), CampusNetworkError>;

    fn logout(account: &LoginAccount, campus: &Self::Campus) -> bool;

    fn get_ip(campus: &Self::Campus) -> Result<IpAddr, CampusNetworkError>;
}

impl LoginAccount {
    pub fn new(username: &str, password: &str, ip: &IpAddr) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            ip: ip.clone(),
        }
    }
}
