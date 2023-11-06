use std::net::IpAddr;

use ccnl_core::backend::{self, CampusNetwork, LoginAccount};

use clap::{clap_derive::*, Parser};
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ArgAccount {
    #[arg(short, long)]
    username: String,

    #[arg(short, long)]
    password: String,

    #[arg(short, long, value_enum)]
    ip: Option<IpAddr>,
}

// TODO: 通过subcommand来配置不同的学校，和他们具体的参数
pub fn main() {
    let args = ArgAccount::parse();
    // 登陆三要素
    let campus = backend::lntu::LntuCampus::HuLuDao;
    let ip = match args.ip {
        Some(ip) => ip,
        None => backend::lntu::Lntu::get_ip(&campus).unwrap(),
    };
    let account = LoginAccount::new(&args.username, &args.password, &ip);
    let result = backend::lntu::Lntu::login(&account, &campus);
    println!("result: {:?}", result)
}
