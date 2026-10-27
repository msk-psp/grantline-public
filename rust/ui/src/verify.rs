use super::*;

#[component]
pub(super) fn VerifyForm(bootstrap: Bootstrap) -> impl IntoView {
    let b = bootstrap;
    if b.probe_subjects.values().all(Vec::is_empty) {
        return view! {<p class="notice">{tr(&b.lang,"Live checks are disabled or no target credentials are configured for this operator.")}</p>}.into_any();
    }
    let selected = if b.probe_subjects.contains_key(&b.service) {
        b.service.clone()
    } else {
        b.probe_subjects.keys().next().cloned().unwrap_or_default()
    };
    let names = b.probe_subjects[&selected].clone();
    let selected_subject = if names.contains(&b.subject) {
        b.subject.clone()
    } else {
        names.first().cloned().unwrap_or_default()
    };
    let system = RwSignal::new(selected);
    let kinds = b.data.service_kinds.clone();
    let is_s3 = RwSignal::new(
        kinds
            .get(&system.get_untracked())
            .is_some_and(|k| k == "s3"),
    );
    let subject = RwSignal::new(selected_subject);
    let resource = RwSignal::new(b.resource.clone());
    let object = RwSignal::new(String::new());
    let table = RwSignal::new(String::new());
    let expected = RwSignal::new("allow".to_owned());
    let busy = RwSignal::new(false);
    let message = RwSignal::new(String::new());
    let current = RwSignal::new(None::<Value>);
    let previous = RwSignal::new(None::<Value>);
    let choices = b.probe_subjects.clone();
    let available = b.probe_subjects.clone();
    let csrf = b.actor.as_ref().map(|a| a.csrf.clone()).unwrap_or_default();
    let lang = b.lang.clone();
    let previous_lang = b.lang.clone();
    let current_lang = b.lang.clone();
    view! {<section class="card">
        <p class="notice">{tr(&b.lang,"Checks use the selected account. Empty prefixes and missing objects leave reads unverified. Object contents are discarded; data rows are not queried.")}</p>
        <form on:submit=move |ev| {
            ev.prevent_default();
            if busy.get_untracked() { return; }
            submit(json!({"csrf":csrf,"system":system.get_untracked(),"subject":subject.get_untracked(),
                "resource":resource.get_untracked(),"object":object.get_untracked(),"table":table.get_untracked(),
                "expected":expected.get_untracked()}), busy, message, current, previous);
        }>
        <label>{tr(&b.lang,"Service instance (environment)")}
            <select prop:value=move ||system.get() on:change=move |ev| {
                let value = event_target_value(&ev);
                subject.set(choices.get(&value).and_then(|s|s.first()).cloned().unwrap_or_default());
                is_s3.set(kinds.get(&value).is_some_and(|k|k=="s3"));
                object.set(String::new());
                table.set(String::new());
                system.set(value);
            }>{b.probe_subjects.keys().map(|s|view!{<option value=s.clone() selected=*s==system.get_untracked()>{s.clone()}</option>}).collect_view()}</select>
        </label>
        <label>{tr(&b.lang,"Subject")}
            <select prop:value=move ||subject.get() on:change=move |ev|subject.set(event_target_value(&ev))>
                {move ||available.get(&system.get()).cloned().unwrap_or_default().into_iter()
                    .map(|s|view!{<option value=s.clone() selected=s==subject.get()>{s.clone()}</option>}).collect_view()}
            </select>
        </label>
        <p class="muted">{tr(&b.lang,"PostgreSQL: db:database checks new-schema creation; schema:database.schema also checks USAGE and table creation. These are ACL checks, not attempted DDL.")}</p>
        <label>{tr(&b.lang,"Resource")}<input required maxlength="1024" placeholder=move||if is_s3.get(){"bucket:example/team"}else{"schema:example.registry"} prop:value=move||resource.get() on:input=move|ev|resource.set(event_target_value(&ev))/></label>
        <fieldset hidden=move||!is_s3.get()>
        <label>{tr(&b.lang,"Sample object key (optional)")}<input maxlength="1024" placeholder="team/sample.txt" prop:value=move||object.get() on:input=move|ev|object.set(event_target_value(&ev))/></label>
        <label>{tr(&b.lang,"Iceberg table (namespace/table, optional)")}<input maxlength="511" placeholder="demo.events/sample" prop:value=move||table.get() on:input=move|ev|table.set(event_target_value(&ev))/></label>
        </fieldset>
        <label>{tr(&b.lang,"Expected access")}
            <select prop:value=move||expected.get() on:change=move|ev|expected.set(event_target_value(&ev))>
                <option value="allow">{tr(&b.lang,"Allowed")}</option><option value="deny">{tr(&b.lang,"Denied")}</option>
            </select>
        </label>
        <div class="actions"><button disabled=move||busy.get()||!b.interactive>{move||tr(&lang,if busy.get(){"Checking…"}else{"Run checks"})}</button></div>
        </form>
        <p role="status">{move||message.get()}</p>
    </section>
    {move||current.get().map(|v|report(&current_lang,&v,"Current check"))}
    {move||previous.get().map(|v|report(&previous_lang,&v,"Previous check"))}}.into_any()
}

fn report(lang: &str, value: &Value, heading: &str) -> AnyView {
    let expected = text(value, "expected");
    let rows = value["checks"].as_array().cloned().unwrap_or_default();
    let grants: BTreeSet<_> = rows
        .iter()
        .filter(|r| r["verdict"] == "deny" && expected == "allow")
        .filter_map(|r| match r["step"].as_str() {
            Some("LIST") => Some((text(value, "resource"), "List".to_owned())),
            Some("HEAD" | "GET") => Some((text(value, "resource"), "Read".to_owned())),
            _ if r["priv"].is_string() => Some((text(r, "resource"), text(r, "priv"))),
            _ => None,
        })
        .collect();
    view! {<section class="card">
        <h2>{tr(lang,heading)}</h2>
        <p><code>{text(value,"subject")}</code>" · "<code>{text(value,"system")}</code>" · "<code>{text(value,"resource")}</code></p>
        <p class="muted">{text(value,"checked_at")}" · "{tr(lang,"Expected access")}": "{tr(lang,if expected=="deny"{"Denied"}else{"Allowed"})}</p>
        <table><thead><tr><th>{tr(lang,"Check")}</th><th>{tr(lang,"Result")}</th><th>"HTTP"</th><th>"ms"</th><th>{tr(lang,"Expected access")}</th><th>{tr(lang,"Details")}</th></tr></thead>
        <tbody>{rows.into_iter().map(|r|{
            let verdict=text(&r,"verdict");
            let label=match verdict.as_str(){"allow"=>"Allowed","deny"=>"Denied",_=>"Unknown"};
            let expectation=if verdict=="unknown"{"Unverified"}else if verdict==expected{"As expected"}else{"Unexpected"};
            view!{<tr><td>{text(&r,"step")}</td><td>{tr(lang,label)}</td><td>{r["status"].as_u64().map(|s|s.to_string()).unwrap_or("—".into())}</td><td>{r["elapsed_ms"].as_u64().map(|s|s.to_string()).unwrap_or("—".into())}</td><td>{tr(lang,expectation)}</td><td>{text(&r,"how")}</td></tr>}
        }).collect_view()}</tbody></table>
        <p class="muted">{tr(lang,"Checks do not apply permissions or verify SQL data rows. Approval and deployment must be followed by the same checks again.")}</p>
        <div class="actions">{grants.into_iter().map(|(resource,privilege)|view!{<a class="button secondary" href=format!("/act?system={}&subject={}&resource={}&priv={}&action=grant&lang={}",encode(&text(value,"system")),encode(&text(value,"subject")),encode(&resource),encode(&privilege),encode(lang))>{tr(lang,"Request access")}" · "{resource.clone()}" "{privilege.clone()}</a>}).collect_view()}</div>
    </section>}.into_any()
}

fn submit(
    value: Value,
    busy: RwSignal<bool>,
    message: RwSignal<String>,
    current: RwSignal<Option<Value>>,
    previous: RwSignal<Option<Value>>,
) {
    busy.set(true);
    message.set(String::new());
    #[cfg(feature = "hydrate")]
    leptos::task::spawn_local(async move {
        use wasm_bindgen::{JsCast, JsValue};
        use wasm_bindgen_futures::JsFuture;
        let result: Result<Value, JsValue> = async {
            let options = web_sys::RequestInit::new();
            options.set_method("POST");
            options.set_credentials(web_sys::RequestCredentials::SameOrigin);
            options.set_body(&JsValue::from_str(&value.to_string()));
            let request = web_sys::Request::new_with_str_and_init("/api/probes", &options)?;
            request.headers().set("Content-Type", "application/json")?;
            let response: web_sys::Response = JsFuture::from(
                web_sys::window()
                    .ok_or(JsValue::NULL)?
                    .fetch_with_request(&request),
            )
            .await?
            .dyn_into()?;
            let body = JsFuture::from(response.text()?)
                .await?
                .as_string()
                .unwrap_or_default();
            if !response.ok() {
                return Err(JsValue::from_str(&body));
            }
            serde_json::from_str(&body).map_err(|_| JsValue::from_str("Invalid probe response"))
        }
        .await;
        match result {
            Ok(report) => {
                previous.set(current.get_untracked());
                current.set(Some(report));
            }
            Err(e) => {
                current.set(None);
                message.set(
                    e.as_string()
                        .unwrap_or_else(|| "Request failed. Check sign-in and refresh.".into())
                        .chars()
                        .take(1000)
                        .collect(),
                );
            }
        }
        busy.set(false);
    });
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (value, current, previous);
        message.set("UI hydration is unavailable".into());
        busy.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_listing_never_displays_a_successful_read() {
        Owner::new().with(||{
            let value=json!({"subject":"alice","system":"objects-staging","resource":"bucket:demo/team","expected":"allow",
                "checks":[{"step":"LIST","verdict":"allow","status":200},{"step":"GET","verdict":"unknown"}]});
            let html=report("ko",&value,"Current check").to_html();
            assert!(html.contains("미검증") && html.contains("GET") && html.contains("alice"));
            assert!(!html.contains("/act?"));
        });
    }
    #[test]
    fn expected_denial_is_not_a_permission_request() {
        Owner::new().with(|| {
            let value =
                json!({"expected":"deny","checks":[{"step":"GET","verdict":"deny","status":403}]});
            let html = report("en", &value, "Current check").to_html();
            assert!(html.contains("As expected"));
            assert!(!html.contains("/act?"));
        });
    }
}
