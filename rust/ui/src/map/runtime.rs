use super::gpu::{Gpu, Palette};
use super::scene::{Camera, Model, Scene, Visible, kind_index};
use super::{FocusInfo, Graph, H, W, route, tr};
use js_sys::Array;
use leptos::prelude::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::{Rc, Weak};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{
    CanvasRenderingContext2d as Ctx, Event, EventTarget, HtmlCanvasElement, HtmlElement,
    HtmlImageElement, KeyboardEvent, MutationObserver, MutationObserverInit, Path2d, PointerEvent,
    ResizeObserver, WheelEvent,
};

fn now() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.)
}
fn find_canvas(root: &HtmlElement, selector: &str) -> Result<HtmlCanvasElement, JsValue> {
    root.query_selector(selector)?
        .ok_or(JsValue::NULL)?
        .dyn_into()
        .map_err(Into::into)
}

struct Driver {
    root: HtmlElement,
    canvas: HtmlCanvasElement,
    labels: HtmlCanvasElement,
    ctx: Ctx,
    gpu: Option<Gpu>,
    palette: Palette,
    model: Model,
    scene: Scene,
    query: String,
    lang: String,
    expanded: Option<String>,
    camera: Camera,
    width: f64,
    height: f64,
    dpr: f64,
    hover: Option<usize>,
    selected: Option<String>,
    focus: Option<usize>,
    active: Option<Rc<Vec<u8>>>,
    active_key: Option<String>,
    state_dirty: bool,
    dirty: bool,
    drag: Option<(i32, i32, f64, f64)>,
    dragged: bool,
    frame: u64,
    scheduled: Option<i32>,
    callback: Option<js_sys::Function>,
    selected_signal: RwSignal<Option<String>>,
    focus_signal: RwSignal<Option<FocusInfo>>,
    icons: Vec<(String, HtmlImageElement)>,
    last_cpu: f64,
    last_event: f64,
}
impl Driver {
    fn schedule(&mut self) {
        if self.scheduled.is_none()
            && let Some(callback) = &self.callback
        {
            self.scheduled =
                web_sys::window().and_then(|w| w.request_animation_frame(callback).ok());
        }
    }
    fn invalidate(&mut self) {
        self.dirty = true;
        self.schedule();
    }
    fn flush(&mut self) {
        if let Some(id) = self.scheduled.take()
            && let Some(window) = web_sys::window()
        {
            let _ = window.cancel_animation_frame(id);
        }
        self.frame();
    }
    fn point(&self, e: &PointerEvent) -> (f64, f64) {
        let r = self.root.get_bounding_client_rect();
        (
            f64::from(e.client_x()) - r.left(),
            f64::from(e.client_y()) - r.top(),
        )
    }
    fn publish_focus(&self) {
        let info = self.focus.and_then(|i| {
            self.scene.nodes.get(i).map(|n| {
                let label = if n.kind == "instance" {
                    format!(
                        "{} · {} {} · {}",
                        n.label,
                        n.count,
                        tr(&self.lang, "Resources"),
                        tr(
                            &self.lang,
                            if self.expanded.as_deref() == n.id.strip_prefix('@') {
                                "Expanded"
                            } else {
                                "Collapsed"
                            }
                        )
                    )
                } else {
                    n.label.clone()
                };
                FocusInfo {
                    id: n.id.clone(),
                    label: format!(
                        "{} · {}",
                        label,
                        n.homes.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                    position: i + 1,
                    total: self.scene.nodes.len(),
                }
            })
        });
        if let Some(info) = &info {
            let _ = self.root.set_attribute("title", &info.label);
        }
        self.focus_signal.set(info);
    }
    fn set_hover(&mut self, hover: Option<usize>) {
        if self.hover != hover {
            self.hover = hover;
            if hover.is_none() {
                let _ = self.root.remove_attribute("title");
            }
            self.last_event = now();
            self.invalidate();
        }
    }
    fn move_pointer(&mut self, e: &PointerEvent) {
        if let Some((x, y, px, py)) = self.drag {
            let (dx, dy) = (e.client_x() - x, e.client_y() - y);
            if dx.abs() + dy.abs() > 3 {
                self.dragged = true;
                self.camera.x = px + f64::from(dx);
                self.camera.y = py + f64::from(dy);
                self.set_hover(None);
                self.invalidate();
            }
        } else {
            let (x, y) = self.point(e);
            let hit = self.scene.hit(self.camera, self.width, x, y);
            if hit != self.hover {
                self.focus = hit;
                self.publish_focus();
                self.set_hover(hit);
            }
        }
    }
    fn choose(&mut self, index: usize) {
        let Some(node) = self.scene.nodes.get(index) else {
            return;
        };
        let id = node.id.clone();
        let instance = node.kind == "instance";
        self.selected = if self.selected.as_ref() == Some(&id) {
            None
        } else {
            Some(id.clone())
        };
        self.selected_signal.set(self.selected.clone());
        if instance {
            self.expanded = if self.expanded.as_deref() == id.strip_prefix('@') {
                None
            } else {
                id.strip_prefix('@').map(str::to_owned)
            };
            self.rebuild();
        }
        self.focus = self.scene.lookup.get(&id).copied();
        self.hover = self.focus;
        self.publish_focus();
        self.last_event = now();
        self.invalidate();
    }
    fn rebuild(&mut self) {
        self.scene = self
            .model
            .scene(&self.query, self.expanded.as_deref(), &self.lang);
        self.upload_scene();
    }
    fn upload_scene(&mut self) {
        if let Some(gpu) = &mut self.gpu {
            gpu.scene(&self.scene);
        }
        let _ = self
            .root
            .set_attribute("data-world-height", &self.scene.height.to_string());
        self.active_key = None;
        self.active = None;
        self.state_dirty = true;
        let _ = self
            .root
            .set_attribute("data-node-count", &self.scene.nodes.len().to_string());
        let _ = self
            .root
            .set_attribute("data-edge-count", &self.scene.edges.len().to_string());
        let _ = self
            .root
            .set_attribute("data-expanded", self.expanded.as_deref().unwrap_or(""));
    }
    fn action(&mut self, action: &str) {
        match action {
            "zoom-in" | "zoom-out" => self.camera.zoom_at(
                if action == "zoom-in" { 1.25 } else { 0.8 },
                self.width / 2.,
                self.height / 2.,
            ),
            "clear" => {
                self.selected = None;
                self.selected_signal.set(None);
                self.hover = None;
            }
            "reset" => {
                self.camera = Camera::default();
                self.hover = None;
                self.focus = None;
                self.selected = None;
                self.selected_signal.set(None);
                if self.expanded.take().is_some() {
                    self.rebuild();
                }
                self.publish_focus();
            }
            _ => return,
        }
        self.last_event = now();
        self.invalidate();
    }
    fn key(&mut self, e: &KeyboardEvent) {
        let key = e.key();
        if key == "Escape" {
            e.prevent_default();
            self.action("reset");
            return;
        }
        if matches!(key.as_str(), "Enter" | " ") {
            e.prevent_default();
            if !e.repeat()
                && let Some(i) = self
                    .focus
                    .or_else(|| (!self.scene.nodes.is_empty()).then_some(0))
            {
                self.choose(i);
            }
            return;
        }
        if matches!(key.as_str(), "PageUp" | "PageDown") {
            e.prevent_default();
            let step = self.height * 0.8;
            if key == "PageUp" {
                self.camera.y += step;
            } else {
                self.camera.y -= step;
            }
            self.set_hover(None);
            self.invalidate();
            return;
        }
        if matches!(
            key.as_str(),
            "ArrowUp" | "ArrowDown" | "ArrowLeft" | "ArrowRight" | "Home" | "End"
        ) && !self.scene.nodes.is_empty()
        {
            e.prevent_default();
            let next = self.scene.navigate(self.focus.unwrap_or(0), &key);
            self.focus = Some(next);
            self.publish_focus();
            self.camera.reveal(
                &self.scene.nodes[next],
                self.width,
                self.height,
                &self.scene,
            );
            self.set_hover(Some(next));
            self.invalidate();
        }
    }
    fn resize(&mut self) {
        self.width = f64::from(self.root.client_width()).max(1.);
        self.height = f64::from(self.root.client_height()).max(1.);
        self.dpr = web_sys::window()
            .map(|w| w.device_pixel_ratio())
            .unwrap_or(1.)
            .clamp(1., 3.);
        let (w, h) = (
            (self.width * self.dpr).round() as u32,
            (self.height * self.dpr).round() as u32,
        );
        for canvas in [&self.canvas, &self.labels] {
            if canvas.width() != w || canvas.height() != h {
                canvas.set_width(w);
                canvas.set_height(h);
            }
        }
        self.invalidate();
    }
    fn theme(&mut self) {
        if let Ok(palette) = Palette::read(&self.root, &self.ctx) {
            self.palette = palette;
            self.invalidate();
        }
    }
    fn active(&self, index: usize) -> bool {
        self.active
            .as_ref()
            .is_some_and(|s| s[self.scene.ids[index]] != 0)
    }
    fn fallback(&self, visible: &Visible) {
        let ctx = &self.ctx;
        let p = &self.palette;
        for range in &visible.edges {
            for e in &self.scene.edges[range.clone()] {
                let hot = self
                    .active
                    .as_ref()
                    .is_some_and(|a| a[e.src] != 0 && a[e.dst] != 0);
                let strength = if hot {
                    1.
                } else if self.active.is_some() {
                    0.05
                } else {
                    0.34
                };
                ctx.set_stroke_style_str(&Palette::css(p.dim(p.edges[e.tone], strength)));
                ctx.set_fill_style_str(&Palette::css(p.dim(p.edges[e.tone], strength)));
                ctx.set_line_width(if hot {
                    2.2
                } else if e.dash == 2. {
                    1.8
                } else {
                    1.2
                });
                let dash = match e.dash as u8 {
                    1 => Array::of2(&2.into(), &3.into()),
                    2 => Array::of2(&5.into(), &4.into()),
                    _ => Array::new(),
                };
                let _ = ctx.set_line_dash(&dash);
                if let Ok(path) =
                    Path2d::new_with_path_string(&route(e.from.0, e.from.1, e.to.0, e.to.1))
                {
                    ctx.stroke_with_path(&path);
                }
                let back = e.to.0 < e.from.0;
                let dir = if back { -1. } else { 1. };
                let x = if back {
                    (e.to.0 + W + 7) as f64
                } else {
                    e.to.0.saturating_sub(7) as f64
                };
                let y = (e.to.1 + H / 2) as f64;
                ctx.begin_path();
                ctx.move_to(x, y);
                ctx.line_to(x - dir * 8., y - 3.5);
                ctx.line_to(x - dir * 8., y + 3.5);
                ctx.close_path();
                ctx.fill();
            }
        }
        for range in &visible.nodes {
            for i in range.clone() {
                let n = &self.scene.nodes[i];
                let border = p.nodes[kind_index(&n.kind)];
                let hot = self.active(i);
                let dim = self.active.is_some() && !hot;
                let border = if dim { p.dim(border, 0.22) } else { border };
                let fill = if self.hover == Some(i) {
                    std::array::from_fn(|c| p.fill[c] + (p.accent[c] - p.fill[c]) * 0.18)
                } else if hot {
                    std::array::from_fn(|c| p.fill[c] + (border[c] - p.fill[c]) * 0.10)
                } else {
                    p.fill
                };
                let fill = if dim { p.dim(fill, 0.22) } else { fill };
                ctx.set_fill_style_str(&Palette::css(fill));
                ctx.set_stroke_style_str(&Palette::css(border));
                ctx.set_line_width(if self.selected.as_ref() == Some(&n.id) {
                    3.5
                } else if self.hover == Some(i) {
                    2.6
                } else if hot {
                    2.2
                } else {
                    1.6
                });
                let dash = if n.kind == "instance" {
                    Array::of2(&2.into(), &3.into())
                } else if matches!(n.kind.as_str(), "svc-account" | "policy") {
                    Array::of2(&4.into(), &3.into())
                } else {
                    Array::new()
                };
                let _ = ctx.set_line_dash(&dash);
                ctx.begin_path();
                let _ = ctx.round_rect_with_f64(n.x as f64, n.y as f64, W as f64, H as f64, 9.);
                ctx.fill();
                ctx.stroke();
            }
        }
        let _ = ctx.set_line_dash(&Array::new());
    }
    fn labels(&self, visible: &Visible) {
        let ctx = &self.ctx;
        let scale = self.camera.scale(self.width, &self.scene);
        let p = &self.palette;
        if scale < 0.22 {
            return;
        }
        ctx.set_fill_style_str(&Palette::css(p.muted));
        ctx.set_font("10px ui-monospace,Menlo,monospace");
        ctx.set_text_align("left");
        for (x, title, count) in &self.scene.columns {
            let _ = ctx.fill_text(&tr(&self.lang, title), *x as f64, (super::TOP - 30) as f64);
            let _ = ctx.fill_text(
                &format!("{count} · a–z"),
                *x as f64,
                (super::TOP - 14) as f64,
            );
        }
        for (x, y, title) in &self.scene.groups {
            let yy = *y as f64 * scale + self.camera.y;
            if yy >= -30. && yy <= self.height + 30. {
                let _ = ctx.fill_text(&tr(&self.lang, title), *x as f64, (*y + 20) as f64);
            }
        }
        for range in &visible.nodes {
            for i in range.clone() {
                let n = &self.scene.nodes[i];
                let label = &self.scene.labels[i];
                let dim = self.active.is_some() && !self.active(i);
                ctx.set_fill_style_str(&Palette::css(if dim {
                    p.dim(p.text, 0.22)
                } else {
                    p.text
                }));
                ctx.set_text_align("left");
                ctx.set_font("12.5px ui-monospace,SFMono-Regular,Menlo,monospace");
                let _ = ctx.fill_text(&label.text, (n.x + 12) as f64, (n.y + 20) as f64);
                ctx.set_fill_style_str(&Palette::css(if dim {
                    p.dim(p.muted, 0.22)
                } else {
                    p.muted
                }));
                ctx.set_font("10px ui-monospace,Menlo,monospace");
                ctx.set_text_align("right");
                let _ = ctx.fill_text(
                    &label.tag,
                    (n.x + W - 12 - label.icons.len() * 19) as f64,
                    (n.y + 20) as f64,
                );
                for (j, icon) in label.icons.iter().enumerate() {
                    let x = (n.x + W - 26 - j * 19) as f64;
                    let y = (n.y + 8) as f64;
                    if let Some((_, image)) = self.icons.iter().find(|(k, _)| k == icon)
                        && image.complete()
                        && image.natural_width() > 0
                    {
                        ctx.set_global_alpha(if dim { 0.22 } else { 1. });
                        let _ = ctx.draw_image_with_html_image_element_and_dw_and_dh(
                            image, x, y, 16., 16.,
                        );
                        ctx.set_global_alpha(1.);
                    } else {
                        ctx.set_font("17px ui-monospace,Menlo,monospace");
                        ctx.set_text_align("left");
                        if icon == "clickhouse" {
                            ctx.set_fill_style_str("#f2c500");
                        }
                        let _ =
                            ctx.fill_text(if icon == "clickhouse" { "▥" } else { "◇" }, x, y + 13.);
                    }
                }
            }
        }
    }
    fn frame(&mut self) {
        self.scheduled = None;
        if self.dirty {
            let start = now();
            self.dirty = false;
            if self.hover.is_none() {
                let _ = self.root.remove_attribute("title");
            }
            self.frame += 1;
            let key = self
                .hover
                .and_then(|i| self.scene.nodes.get(i).map(|n| n.id.clone()))
                .or_else(|| self.selected.clone());
            if key != self.active_key {
                self.active = key.as_deref().map(|id| self.model.active(id));
                self.active_key = key;
                self.state_dirty = true;
            }
            if self.state_dirty {
                if let Some(gpu) = &mut self.gpu {
                    if let Err(error) = gpu.state(self.active.as_ref().map(|s| s.as_slice())) {
                        let _ = self
                            .root
                            .set_attribute("data-gpu-error", &format!("{error:?}"));
                        self.gpu = None;
                        let _ = self
                            .root
                            .set_attribute("data-renderer", "canvas2d-fallback");
                    }
                }
                self.state_dirty = false;
            }
            let visible = self.scene.visible(self.camera, self.width, self.height);
            let draws = if let Some(gpu) = &mut self.gpu {
                gpu.draw(
                    &self.scene,
                    &visible,
                    self.camera,
                    (self.width, self.height),
                    (self.canvas.width(), self.canvas.height()),
                    &self.palette,
                    self.active.is_some(),
                    self.hover.map(|i| self.scene.ids[i]),
                    self.selected
                        .as_ref()
                        .and_then(|id| self.model.index.ids.get(id).copied()),
                    self.frame,
                )
            } else {
                0
            };
            let ctx = &self.ctx;
            let _ = ctx.set_transform(1., 0., 0., 1., 0., 0.);
            ctx.clear_rect(
                0.,
                0.,
                f64::from(self.labels.width()),
                f64::from(self.labels.height()),
            );
            let s = self.camera.scale(self.width, &self.scene) * self.dpr;
            let _ = ctx.set_transform(
                s,
                0.,
                0.,
                s,
                self.camera.x * self.dpr,
                self.camera.y * self.dpr,
            );
            if self.gpu.is_none() {
                self.fallback(&visible);
            }
            self.labels(&visible);
            let active_nodes = self
                .active
                .as_ref()
                .map(|a| a.iter().filter(|&&v| v != 0).count());
            self.last_cpu = now() - start;
            let stats = serde_json::json!({"frame":self.frame,"cpuMs":self.last_cpu,"eventToSubmitMs":if self.last_event>0.{Some(now()-self.last_event)}else{None},"nodes":self.scene.nodes.len(),"edges":self.scene.edges.len(),"visibleNodes":visible.nodes.iter().map(|r|r.len()).sum::<usize>(),"visibleEdges":visible.edges.iter().map(|r|r.len()).sum::<usize>(),"activeNodes":active_nodes,"drawCalls":draws,"geometryUploads":self.gpu.as_ref().map(|g|g.geometry_uploads),"stateUploads":self.gpu.as_ref().map(|g|g.state_uploads),"hover":self.hover.map(|i|&self.scene.nodes[i].id)});
            let _ = self
                .root
                .set_attribute("data-graph-frame", &stats.to_string());
            self.last_event = 0.;
            if let Ok(event) = Event::new("grantline-map-frame") {
                let _ = self.root.dispatch_event(&event);
            }
        }
        if let Some(gpu) = &mut self.gpu {
            let pending = gpu.poll();
            if let Some((frame, ms)) = gpu.measured {
                let _ = self.root.set_attribute(
                    "data-graph-gpu",
                    &serde_json::json!({"frame":frame,"ms":ms}).to_string(),
                );
            }
            if pending {
                self.schedule();
            }
        }
    }
}

type Listener = (EventTarget, &'static str, Closure<dyn FnMut(Event)>);
pub(super) struct Runtime {
    driver: Rc<RefCell<Driver>>,
    listeners: Vec<Listener>,
    resize: ResizeObserver,
    mutation: MutationObserver,
    _raf: Closure<dyn FnMut(f64)>,
    _resize: Closure<dyn FnMut()>,
    _mutation: Closure<dyn FnMut()>,
}
impl Runtime {
    #[allow(clippy::too_many_arguments)]
    pub fn mount(
        root: HtmlElement,
        graph: Graph,
        kinds: BTreeMap<String, String>,
        query: String,
        lang: String,
        selected: RwSignal<Option<String>>,
        focus: RwSignal<Option<FocusInfo>>,
    ) -> Result<Self, JsValue> {
        let canvas = find_canvas(&root, ".map-gpu")?;
        let labels = find_canvas(&root, ".map-labels")?;
        let ctx: Ctx = labels.get_context("2d")?.ok_or(JsValue::NULL)?.dyn_into()?;
        let palette = Palette::read(&root, &ctx)?;
        let model = Model::new(graph, kinds);
        let scene = model.scene(&query, None, &lang);
        let gpu = match Gpu::new(&canvas, model.index.names.len()) {
            Ok(gpu) => Some(gpu),
            Err(error) => {
                let _ = root.set_attribute(
                    "data-gpu-error",
                    &error
                        .as_string()
                        .unwrap_or_else(|| "WebGL2 initialization failed".into()),
                );
                None
            }
        };
        let driver = Rc::new(RefCell::new(Driver {
            root: root.clone(),
            canvas,
            labels,
            ctx,
            gpu,
            palette,
            model,
            scene,
            query,
            lang,
            expanded: None,
            camera: Camera::default(),
            width: 1.,
            height: 1.,
            dpr: 1.,
            hover: None,
            selected: None,
            focus: None,
            active: None,
            active_key: None,
            state_dirty: true,
            dirty: true,
            drag: None,
            dragged: false,
            frame: 0,
            scheduled: None,
            callback: None,
            selected_signal: selected,
            focus_signal: focus,
            icons: Vec::new(),
            last_cpu: 0.,
            last_event: 0.,
        }));
        let weak = Rc::downgrade(&driver);
        let raf = Closure::wrap(Box::new(move |_: f64| {
            if let Some(d) = weak.upgrade() {
                d.borrow_mut().frame();
            }
        }) as Box<dyn FnMut(f64)>);
        driver.borrow_mut().callback =
            Some(raf.as_ref().unchecked_ref::<js_sys::Function>().clone());
        let weak = Rc::downgrade(&driver);
        let resize_callback = Closure::wrap(Box::new(move || {
            if let Some(d) = weak.upgrade() {
                d.borrow_mut().resize();
            }
        }) as Box<dyn FnMut()>);
        let resize = ResizeObserver::new(resize_callback.as_ref().unchecked_ref())?;
        resize.observe(&root);
        let weak = Rc::downgrade(&driver);
        let mutation_callback = Closure::wrap(Box::new(move || {
            if let Some(d) = weak.upgrade() {
                d.borrow_mut().theme();
            }
        }) as Box<dyn FnMut()>);
        let mutation = MutationObserver::new(mutation_callback.as_ref().unchecked_ref())?;
        if let Some(html) = root.owner_document().and_then(|d| d.document_element()) {
            let options = MutationObserverInit::new();
            options.set_attributes(true);
            options.set_attribute_filter(&Array::of1(&"data-theme".into()));
            mutation.observe_with_options(&html, &options)?;
        }
        let mut result = Self {
            driver,
            listeners: Vec::new(),
            resize,
            mutation,
            _raf: raf,
            _resize: resize_callback,
            _mutation: mutation_callback,
        };
        result.listen(root.clone().into(), "pointermove", |d, e| {
            if let Some(e) = e.dyn_ref::<PointerEvent>() {
                d.move_pointer(e);
            }
        })?;
        result.listen(root.clone().into(), "pointerdown", |d, e| {
            if let Some(e) = e.dyn_ref::<PointerEvent>()
                && e.button() == 0
            {
                d.dragged = false;
                d.drag = Some((e.client_x(), e.client_y(), d.camera.x, d.camera.y));
                let _ = d.root.set_pointer_capture(e.pointer_id());
                let _ = d.root.class_list().add_1("dragging");
            }
        })?;
        result.listen(root.clone().into(), "pointerup", |d, e| {
            d.drag = None;
            let _ = d.root.class_list().remove_1("dragging");
            if let Some(e) = e.dyn_ref::<PointerEvent>() {
                let _ = d.root.release_pointer_capture(e.pointer_id());
            }
        })?;
        result.listen(root.clone().into(), "pointercancel", |d, _| {
            d.drag = None;
            d.dragged = true;
            let _ = d.root.class_list().remove_1("dragging");
        })?;
        result.listen(root.clone().into(), "pointerleave", |d, _| {
            d.set_hover(None);
        })?;
        result.listen(root.clone().into(), "click", |d, e| {
            if !d.dragged
                && let Some(e) = e.dyn_ref::<web_sys::MouseEvent>()
            {
                let r = d.root.get_bounding_client_rect();
                if let Some(i) = d.scene.hit(
                    d.camera,
                    d.width,
                    f64::from(e.client_x()) - r.left(),
                    f64::from(e.client_y()) - r.top(),
                ) {
                    d.choose(i);
                }
            }
        })?;
        result.listen(root.clone().into(), "wheel", |d, e| {
            if let Some(e) = e.dyn_ref::<WheelEvent>() {
                e.prevent_default();
                if e.shift_key() {
                    d.camera.y -= e.delta_y();
                } else {
                    let r = d.root.get_bounding_client_rect();
                    d.camera.zoom_at(
                        if e.delta_y() < 0. { 1.1 } else { 1. / 1.1 },
                        f64::from(e.client_x()) - r.left(),
                        f64::from(e.client_y()) - r.top(),
                    );
                }
                d.set_hover(None);
                d.invalidate();
            }
        })?;
        result.listen(root.clone().into(), "keydown", |d, e| {
            if let Some(e) = e.dyn_ref::<KeyboardEvent>() {
                d.key(e);
            }
        })?;
        result.listen(root.clone().into(), "focus", |d, _| {
            if !d.scene.nodes.is_empty() {
                let i = d.focus.unwrap_or(0);
                d.focus = Some(i);
                d.publish_focus();
                d.set_hover(Some(i));
            }
        })?;
        result.listen(root.clone().into(), "blur", |d, _| {
            d.set_hover(None);
        })?;
        result.listen(root.clone().into(), "grantline-map-command", |d, e| {
            if let Some(action) = e
                .dyn_ref::<web_sys::CustomEvent>()
                .and_then(|e| e.detail().as_string())
            {
                d.action(&action);
            }
        })?;
        let gpu_canvas: EventTarget = result.driver.borrow().canvas.clone().into();
        result.listen(gpu_canvas.clone(), "webglcontextlost", |d, e| {
            e.prevent_default();
            d.gpu = None;
            let _ = d.root.set_attribute("data-renderer", "canvas2d-fallback");
            d.invalidate();
        })?;
        result.listen(gpu_canvas, "webglcontextrestored", |d, _| {
            d.gpu = Gpu::new(&d.canvas, d.model.index.names.len()).ok();
            if let Some(g) = &mut d.gpu {
                g.scene(&d.scene);
                let _ = d.root.remove_attribute("data-gpu-error");
            }
            d.state_dirty = true;
            let _ = d.root.set_attribute(
                "data-renderer",
                if d.gpu.is_some() {
                    "webgl2"
                } else {
                    "canvas2d-fallback"
                },
            );
            d.invalidate();
        })?;
        if let Some(window) = web_sys::window() {
            result.listen(window.clone().into(), "resize", |d, _| d.resize())?;
            if let Some(media) = window.match_media("(prefers-color-scheme: dark)")? {
                result.listen(media.into(), "change", |d, _| d.theme())?;
            }
        }
        for (kind, path) in [
            ("postgres", "/static/postgresql.png"),
            ("s3", "/static/seaweedfs.png"),
        ] {
            let image = HtmlImageElement::new()?;
            result.listen(image.clone().into(), "load", |d, _| d.invalidate())?;
            image.set_src(path);
            result.driver.borrow_mut().icons.push((kind.into(), image));
        }
        {
            let mut d = result.driver.borrow_mut();
            d.upload_scene();
            let _ = d.root.set_attribute(
                "data-renderer",
                if d.gpu.is_some() {
                    "webgl2"
                } else {
                    "canvas2d-fallback"
                },
            );
            d.resize();
        }
        Ok(result)
    }
    fn listen(
        &mut self,
        target: EventTarget,
        name: &'static str,
        mut callback: impl FnMut(&mut Driver, Event) + 'static,
    ) -> Result<(), JsValue> {
        let driver: Weak<RefCell<Driver>> = Rc::downgrade(&self.driver);
        let closure = Closure::wrap(Box::new(move |event: Event| {
            if let Some(d) = driver.upgrade() {
                let start = now();
                let mut d = d.borrow_mut();
                callback(&mut d, event);
                // Discrete highlights submit now; camera motion stays frame-coalesced.
                if d.dirty
                    && (matches!(name, "pointerleave" | "keydown")
                        || name == "pointermove" && d.drag.is_none())
                {
                    d.last_event = start;
                    d.flush();
                }
            }
        }) as Box<dyn FnMut(Event)>);
        target.add_event_listener_with_callback(name, closure.as_ref().unchecked_ref())?;
        self.listeners.push((target, name, closure));
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.resize.disconnect();
        self.mutation.disconnect();
        for (target, name, closure) in &self.listeners {
            let _ =
                target.remove_event_listener_with_callback(name, closure.as_ref().unchecked_ref());
        }
        if let Some(id) = self.driver.borrow_mut().scheduled.take()
            && let Some(window) = web_sys::window()
        {
            let _ = window.cancel_animation_frame(id);
        }
        self.driver.borrow_mut().callback = None;
    }
}
