use serde::Deserialize;

/**
 * 扫描的语言类型枚举
 */
#[derive(Debug, Deserialize)]
pub enum LangType {

   JAVA,
   PHP,
   GO

}
/**
 * 规则文件规则类型枚举
 */
#[derive(Debug, Deserialize)]
pub enum RuleCondition {

   Contain,
   Regex

}

/**
 * 开发框架枚举
 */
#[derive(Debug, Deserialize, Clone)]
pub enum Framwork {

   Spring,
   Struts,
   Struts2,
   Laravel,
   ThinkPhp,
   YII,
   None

}


/**
 * ORM框架枚举
 */
#[derive(Debug, Deserialize)]
pub enum ORM {

   Mybatis,
   Hibernate,
   None

}