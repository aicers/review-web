use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    ModuleName, Node, NodeStatus, NodeStatusQuery, NodeStatusTotalCount,
};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, Object, Result,
};
use roxy::ResourceUsage;
use std::collections::{HashMap, HashSet};

#[Object]
impl NodeStatusQuery {
    /// A list of status of all the nodes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_status_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }
}

#[allow(clippy::too_many_lines)]
async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
    let agents = ctx.data::<BoxedAgentManager>()?;
    let apps = agents.online_apps_by_host_id().await?;
    let mut usages: HashMap<String, ResourceUsage> = HashMap::new();
    let mut ping: HashMap<String, i64> = HashMap::new();
    for hostname in apps.keys() {
        let Ok(usage) = agents.get_resource_usage(hostname).await else {
            continue;
        };
        usages.insert(
            hostname.clone(),
            ResourceUsage {
                cpu_usage: usage.cpu_usage,
                total_memory: usage.total_memory,
                used_memory: usage.used_memory,
                total_disk_space: usage.total_disk_space,
                used_disk_space: usage.used_disk_space,
            },
        );
        let Ok(rtt) = agents.ping(hostname).await else {
            continue;
        };
        ping.insert(hostname.clone(), rtt);
    }

    let review_usage = roxy::resource_usage().await;
    let review_hostname = roxy::hostname();

    let store = crate::graphql::get_store(ctx).await?;
    let (node_list, has_previous, has_next): (Vec<(String, Node)>, bool, bool) = {
        let map = store.node_map();
        super::super::load_nodes(&map, after, before, first, last)?
    };

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, NodeStatusTotalCount);

    for (k, ev) in node_list {
        let (
            review,
            piglet,
            giganto,
            reconverge,
            hog,
            cpu_usage,
            total_memory,
            used_memory,
            total_disk_space,
            used_disk_space,
            ping,
            piglet_config,
            reconverge_config,
            hog_config,
        ) = match ev.settings.as_ref().map(|settings| &settings.hostname) {
            Some(hostname) => {
                if let (Some(modules), Some(usage), Some(ping)) =
                    (apps.get(hostname), usages.get(hostname), ping.get(hostname))
                {
                    let module_names = modules
                        .iter()
                        .map(|(_, m)| m.as_str())
                        .collect::<HashSet<&str>>();
                    let (review, piglet, giganto, reconverge, hog) = (
                        module_names.contains(ModuleName::Review.as_ref()),
                        module_names.contains(ModuleName::Piglet.as_ref()),
                        module_names.contains(ModuleName::Giganto.as_ref()),
                        module_names.contains(ModuleName::Reconverge.as_ref()),
                        module_names.contains(ModuleName::Hog.as_ref()),
                    );
                    let piglet_config = if piglet {
                        agents
                            .get_config(hostname, ModuleName::Piglet.as_ref())
                            .await
                            .ok()
                            .and_then(|cfg| match cfg {
                                review_protocol::types::Config::Piglet(piglet_config) => {
                                    Some(piglet_config.into())
                                }
                                _ => None,
                            })
                    } else {
                        None
                    };
                    let reconverge_config = if reconverge {
                        agents
                            .get_config(hostname, ModuleName::Reconverge.as_ref())
                            .await
                            .ok()
                            .and_then(|cfg| match cfg {
                                review_protocol::types::Config::Reconverge(reconverge_config) => {
                                    Some(reconverge_config.into())
                                }
                                _ => None,
                            })
                    } else {
                        None
                    };
                    let hog_config = if hog {
                        agents
                            .get_config(hostname, ModuleName::Hog.as_ref())
                            .await
                            .ok()
                            .and_then(|cfg| match cfg {
                                review_protocol::types::Config::Hog(hog_config) => {
                                    Some(hog_config.into())
                                }
                                _ => None,
                            })
                    } else {
                        None
                    };
                    (
                        Some(review),
                        Some(piglet),
                        Some(giganto),
                        Some(reconverge),
                        Some(hog),
                        Some(usage.cpu_usage),
                        Some(usage.total_memory),
                        Some(usage.used_memory),
                        Some(usage.total_disk_space),
                        Some(usage.used_disk_space),
                        Some(*ping),
                        piglet_config,
                        reconverge_config,
                        hog_config,
                    )
                } else if !review_hostname.is_empty() && &review_hostname == hostname {
                    (
                        Some(true),
                        None,
                        None,
                        None,
                        None,
                        Some(review_usage.cpu_usage),
                        Some(review_usage.total_memory),
                        Some(review_usage.used_memory),
                        Some(review_usage.total_disk_space),
                        Some(review_usage.used_disk_space),
                        None,
                        None,
                        None,
                        None,
                    )
                } else {
                    (
                        None, None, None, None, None, None, None, None, None, None, None, None,
                        None, None,
                    )
                }
            }
            None => (
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            ),
        };
        connection.edges.push(Edge::new(
            k,
            NodeStatus::new(
                ev.id,
                ev.name,
                cpu_usage,
                total_memory,
                used_memory,
                total_disk_space,
                used_disk_space,
                ping,
                review,
                piglet,
                piglet_config,
                giganto,
                reconverge,
                reconverge_config,
                hog,
                hog_config,
            ),
        ));
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn check_node_status_list_ordering() {
        let schema = TestSchema::new().await;

        // Insert 5 nodes
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test1",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        review: true,
                        reviewPort: 1111,
                        reviewWebPort: 1112,
                        piglet: false,
                        pigletGigantoIp: null,
                        pigletGigantoPort: null,
                        pigletReviewIp: null,
                        pigletReviewPort: null,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        html: false,
                        txt: false,
                        smtpEml: false,
                        ftp: false,
                        giganto: false,
                        gigantoIngestionIp: null,
                        gigantoIngestionPort: null,
                        gigantoPublishIp: null,
                        gigantoPublishPort: null,
                        gigantoGraphqlIp: null,
                        gigantoGraphqlPort: null,
                        retentionPeriod: null,
                        reconverge: false,
                        reconvergeReviewIp: null,
                        reconvergeReviewPort: null,
                        reconvergeGigantoIp: null,
                        reconvergeGigantoPort: null,
                        hog: false,
                        hogReviewIp: null,
                        hogReviewPort: null,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: false,
                        protocolList: {},
                        sensors: false,
                        sensorList: {},
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test2",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        review: true,
                        reviewPort: 1111,
                        reviewWebPort: 1112,
                        piglet: false,
                        pigletGigantoIp: null,
                        pigletGigantoPort: null,
                        pigletReviewIp: null,
                        pigletReviewPort: null,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        html: false,
                        txt: false,
                        smtpEml: false,
                        ftp: false,
                        giganto: false,
                        gigantoIngestionIp: null,
                        gigantoIngestionPort: null,
                        gigantoPublishIp: null,
                        gigantoPublishPort: null,
                        gigantoGraphqlIp: null,
                        gigantoGraphqlPort: null,
                        retentionPeriod: null,
                        reconverge: false,
                        reconvergeReviewIp: null,
                        reconvergeReviewPort: null,
                        reconvergeGigantoIp: null,
                        reconvergeGigantoPort: null,
                        hog: false,
                        hogReviewIp: null,
                        hogReviewPort: null,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: false,
                        protocolList: {},
                        sensors: false,
                        sensorList: {},
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test3",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        review: true,
                        reviewPort: 1111,
                        reviewWebPort: 1112,
                        piglet: false,
                        pigletGigantoIp: null,
                        pigletGigantoPort: null,
                        pigletReviewIp: null,
                        pigletReviewPort: null,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        html: false,
                        txt: false,
                        smtpEml: false,
                        ftp: false,
                        giganto: false,
                        gigantoIngestionIp: null,
                        gigantoIngestionPort: null,
                        gigantoPublishIp: null,
                        gigantoPublishPort: null,
                        gigantoGraphqlIp: null,
                        gigantoGraphqlPort: null,
                        retentionPeriod: null,
                        reconverge: false,
                        reconvergeReviewIp: null,
                        reconvergeReviewPort: null,
                        reconvergeGigantoIp: null,
                        reconvergeGigantoPort: null,
                        hog: false,
                        hogReviewIp: null,
                        hogReviewPort: null,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: false,
                        protocolList: {},
                        sensors: false,
                        sensorList: {},
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "2"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test4",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        review: true,
                        reviewPort: 1111,
                        reviewWebPort: 1112,
                        piglet: false,
                        pigletGigantoIp: null,
                        pigletGigantoPort: null,
                        pigletReviewIp: null,
                        pigletReviewPort: null,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        html: false,
                        txt: false,
                        smtpEml: false,
                        ftp: false,
                        giganto: false,
                        gigantoIngestionIp: null,
                        gigantoIngestionPort: null,
                        gigantoPublishIp: null,
                        gigantoPublishPort: null,
                        gigantoGraphqlIp: null,
                        gigantoGraphqlPort: null,
                        retentionPeriod: null,
                        reconverge: false,
                        reconvergeReviewIp: null,
                        reconvergeReviewPort: null,
                        reconvergeGigantoIp: null,
                        reconvergeGigantoPort: null,
                        hog: false,
                        hogReviewIp: null,
                        hogReviewPort: null,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: false,
                        protocolList: {},
                        sensors: false,
                        sensorList: {},
                        )
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "3"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test5",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        review: true,
                        reviewPort: 1111,
                        reviewWebPort: 1112,
                        piglet: false,
                        pigletGigantoIp: null,
                        pigletGigantoPort: null,
                        pigletReviewIp: null,
                        pigletReviewPort: null,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        html: false,
                        txt: false,
                        smtpEml: false,
                        ftp: false,
                        giganto: false,
                        gigantoIngestionIp: null,
                        gigantoIngestionPort: null,
                        gigantoPublishIp: null,
                        gigantoPublishPort: null,
                        gigantoGraphqlIp: null,
                        gigantoGraphqlPort: null,
                        retentionPeriod: null,
                        reconverge: false,
                        reconvergeReviewIp: null,
                        reconvergeReviewPort: null,
                        reconvergeGigantoIp: null,
                        reconvergeGigantoPort: null,
                        hog: false,
                        hogReviewIp: null,
                        hogReviewPort: null,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: false,
                        protocolList: {},
                        sensors: false,
                        sensorList: {},
                    )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "4"}"#);

        // Test first, last, after, before in refernce to test3 node
        let res = schema
            .execute(r#"{nodeStatusList(first:5){edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}},{node: {name: "test2"}},{node: {name: "test3"}},{node: {name: "test4"}},{node: {name: "test5"}}]}}"#
        );

        let res = schema
            .execute(r#"{nodeStatusList(last:5){edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}},{node: {name: "test2"}},{node: {name: "test3"}},{node: {name: "test4"}},{node: {name: "test5"}}]}}"#
        );

        let res = schema
            .execute(r#"{nodeStatusList(last:2, before:"dGVzdDM="){edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}},{node: {name: "test2"}}]}}"#
        );

        let res = schema
            .execute(r#"{nodeStatusList(first:2, after:"dGVzdDM="){edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test4"}},{node: {name: "test5"}}]}}"#
        );
    }
}
