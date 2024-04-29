pub mod config;
pub mod rule;
pub mod unauthorized;

/**
 * 未授权结构体
 * @Field code 响应码
 * @Field body 响应体
 * @Field url 对应的url
 */
pub struct UnauthorizedInterface {
    pub code: u16,
    pub body: String,
    pub url: String,
}

// 类型别名
pub type Interfaces = Vec<String>;