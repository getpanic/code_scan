use serde::Deserialize;

use crate::enums::RuleCondition;

/**
 * @Struct Rule 检测规则
 * @Field keyword 匹配关键字
 * @Field note 备注
 * @Field condition 匹配规则：0-包含，1-正则
 */
#[derive(Deserialize, Debug)]
pub struct Rule{

    pub keyword: String,

    pub note: String,

    pub condition: RuleCondition

}