# 贡献

由于有的学校可能有多个校区而有的学校只有一个校区，为了抹平这种差异，我们提供了两个 trait: `CampusNetworkCampus` 和 `CampusNetwork`

对于有多个校区的学校应对每个分校区实现 `CampusNetworkCampus`, 里面包含了 `login_`, `logout_`, `get_ip_` 三个要实现的函数，接收账号，密码，
ip，实现登陆功能，`get_ip_`是当未提供登陆ip时用于获取缺省的IP地址。最后为学校统一实现 `CampusNetworkCampus` 主要是 **match** 不同的校区
 
对于只有一个校区的学校，我们希望当成有多个校区的学校来实现，即把当前校区当成一个分校区，实现 `CampusNetworkCampus`, 然后为学校统一实现
`CampusNetwork` 这将方便以后学校真的发展了分校区

这样的设计也是为了方便可以通过代码直接生成 **ccnl-cli** 项目的代码，自动构建用于校园网登陆的命令行工具

example:
```rust
pub struct School {}
pub struct SchoolCampus1 {}
pub struct SchoolCampus2 {}

pub enum SchoolCampus{
  Campus1,
  Campus2,
  Campus3,
  // .
  // .
  // .
  CampusN,
}

impl CampusNetwork for School{
    type Campus = SchoolCampus
  
      fn login(account: &LoginAccount, campus: &Self::Campus) -> Result<(), CampusNetworkError> {}

    fn logout(account: &LoginAccount, campus: &Self::Campus) -> bool {}

    fn get_ip(campus: &Self::Campus) -> Result<IpAddr, CampusNetworkError> {}
}

impl CampusNetworkCampus for SchoolCampusX{
    fn login(account: &LoginAccount) -> Result<(), CampusNetworkError> {}

    fn logout(account: &LoginAccount) -> bool {}

    fn get_ip() -> Result<IpAddr, CampusNetworkError> {}
}
```
