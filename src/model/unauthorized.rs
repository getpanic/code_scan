use serde::Deserialize;

/**
 * 配置文件中的未授权配置
 * @Field prefix url前缀
 * @Field rule 判断是否未授权的规则
 * @Field valid 是否需要进行验证
 */
#[derive(Deserialize, Debug)]
pub struct Unauthorized {
    pub prefix: String,
    pub rule: UnauthorizedRule,
    pub valid: bool
}

/**
 * 验证未授权的规则结构体
 * @Field status_code 响应体规则
 * @Field reponse_body 响应体规则
 */
#[derive(Deserialize, Debug)]
pub struct UnauthorizedRule {
    pub status_code: Vec<u16>,
    pub response_body: Vec<Match>
}

/**
 * 响应体命中规则结构体
 * @Field match_rule 命中枚举值
 * @Field value 具体的值
 */
#[derive(Deserialize, Debug, Clone)]
pub struct Match {
    pub match_rule: String,
    pub value: String
}

// /**
//  * 命中规则类型
//  * @Enum EQ 等于
//  * @Enum NE 不等于
//  * @Enum CONTAIN 包含
//  */
// #[derive(Deserialize, Debug)]
// pub enum MatchConditionEnum {
//     Regex = 1,
//     CONTAIN = 2,
//     NOTCONTAIN = 3
// }