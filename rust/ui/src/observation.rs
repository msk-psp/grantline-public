use super::*;

impl Unread {
    pub(super) fn is_limitation(&self) -> bool {
        matches!(self.category.as_str(), "excluded" | "unsupported")
    }
}

fn row(lang: &str, gap: &Unread) -> AnyView {
    let label = match gap.category.as_str() {
        "excluded" => "Excluded by configuration",
        "unsupported" => "Unsupported privilege semantics",
        _ => "Read failed",
    };
    view! {<div class="observation-gap">
        <div class="observation-entities"><code class="entity">{gap.system.clone()}</code><span class="badge">{tr(lang,label)}</span>
        {gap.subjects.iter().chain(gap.privileges.iter()).chain(gap.prefixes.iter()).filter(|s|!s.is_empty()).map(|s|view!{<code class="entity">{s.clone()}</code>}).collect_view()}</div>
        <p>{gap.note.clone()}</p>
    </div>}.into_any()
}

pub(super) fn notices(b: &Bootstrap) -> AnyView {
    let gaps: Vec<_> = b
        .data
        .snapshot
        .unobserved
        .iter()
        .filter(|u| {
            (b.service.is_empty() || u.system == b.service)
                && (b.environment.is_empty()
                    || b.data
                        .environments
                        .get(&b.environment)
                        .is_some_and(|systems| systems.contains(&u.system)))
        })
        .collect();
    let failures: Vec<_> = gaps.iter().filter(|u| !u.is_limitation()).collect();
    let limits: Vec<_> = gaps.iter().filter(|u| u.is_limitation()).collect();
    let unverified = b
        .data
        .plan
        .unverified
        .iter()
        .filter(|g| matched(b, g))
        .count();
    view! {
        {(!failures.is_empty()).then(||view!{<div role="status" class="notice warning observation-failures"><strong>{tr(&b.lang,"Some permissions could not be read; affected access is unknown.")}</strong>{failures.iter().map(|u|row(&b.lang,u)).collect_view()}</div>})}
        {(unverified>0).then(||view!{<p role="status" class="notice warning">{tr(&b.lang,"Requested permissions could not be verified; no changes are planned for them.")}" "{unverified}</p>})}
        {(!limits.is_empty()).then(||view!{<details class="notice observation-limits"><summary>{tr(&b.lang,"Observation scope and limitations")}" ("{limits.len()}")"</summary><p class="muted">{tr(&b.lang,"Excluded or unsupported permissions remain unknown. Other observed permissions are still shown.")}</p>{limits.iter().map(|u|row(&b.lang,u)).collect_view()}</details>})}
    }.into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_are_collapsed_but_failures_and_unverified_intent_stay_visible() {
        Owner::new().with(|| {
            let mut b = Bootstrap {
                lang: "en".into(),
                ..Default::default()
            };
            b.data.snapshot.unobserved.push(Unread {
                system: "warehouse".into(),
                category: "excluded".into(),
                note: "Database scratch excluded".into(),
                ..Default::default()
            });
            let html = notices(&b).to_html();
            assert!(
                html.contains("<details") && html.contains("Observation scope and limitations")
            );
            assert!(!html.contains("<details open") && !html.contains("observation-failures"));
            b.data.snapshot.unobserved.push(Unread {
                system: "warehouse".into(),
                note: "Connection failed".into(),
                ..Default::default()
            });
            b.data.plan.unverified.push(Grant {
                system: "warehouse".into(),
                ..Default::default()
            });
            let html = notices(&b).to_html();
            assert!(html.contains("observation-failures") && html.contains("Connection failed"));
            assert!(html.contains("Requested permissions could not be verified"));
            b.service = "another".into();
            let html = notices(&b).to_html();
            assert!(!html.contains("Database scratch") && !html.contains("Connection failed"));
        });
    }
}
