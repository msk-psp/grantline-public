use super::scene::{Camera, Scene, Visible, kind_index};
use super::{COL, H, W};
use js_sys::{Float32Array, Object, Reflect};
use std::collections::{HashMap, VecDeque};
use std::ops::Range;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{
    CanvasRenderingContext2d, HtmlCanvasElement, WebGl2RenderingContext as Gl, WebGlBuffer,
    WebGlProgram, WebGlQuery, WebGlShader, WebGlTexture, WebGlUniformLocation,
    WebGlVertexArrayObject,
};

#[derive(Clone)]
pub(super) struct Palette {
    pub nodes: Vec<[f32; 3]>,
    pub edges: Vec<[f32; 3]>,
    pub bg: [f32; 3],
    pub fill: [f32; 3],
    pub accent: [f32; 3],
    pub text: [f32; 3],
    pub muted: [f32; 3],
}
impl Palette {
    pub fn read(
        root: &web_sys::HtmlElement,
        ctx: &CanvasRenderingContext2d,
    ) -> Result<Self, JsValue> {
        // Labels leave a world transform behind; color sampling uses device pixels.
        ctx.set_transform(1., 0., 0., 1., 0., 0.)?;
        ctx.set_global_alpha(1.);
        ctx.set_global_composite_operation("source-over")?;
        let style = web_sys::window()
            .ok_or(JsValue::NULL)?
            .get_computed_style(root)?
            .ok_or(JsValue::NULL)?;
        // Let the browser parse CSS colors, including color-mix and theme variables.
        let color = |name: &str| -> Result<[f32; 3], JsValue> {
            ctx.clear_rect(0., 0., 1., 1.);
            ctx.set_fill_style_str(style.get_property_value(name)?.trim());
            ctx.fill_rect(0., 0., 1., 1.);
            let p = ctx.get_image_data(0., 0., 1., 1.)?.data();
            Ok([p[0] as f32 / 255., p[1] as f32 / 255., p[2] as f32 / 255.])
        };
        let bg = color("--bg")?;
        Ok(Self {
            nodes: vec![
                color("--map-read")?,
                color("--map-service")?,
                color("--map-write")?,
                color("--map-group")?,
                color("--muted")?,
                color("--muted")?,
            ],
            edges: vec![
                color("--map-read")?,
                color("--map-write")?,
                color("--map-admin")?,
                color("--map-member")?,
                color("--map-group")?,
                color("--muted")?,
            ],
            bg,
            fill: color("--map-node")?,
            accent: color("--accent")?,
            text: color("--text")?,
            muted: color("--muted")?,
        })
    }
    pub fn css(rgb: [f32; 3]) -> String {
        format!(
            "rgb({},{},{})",
            (rgb[0] * 255.).round() as u8,
            (rgb[1] * 255.).round() as u8,
            (rgb[2] * 255.).round() as u8
        )
    }
    pub fn dim(&self, color: [f32; 3], amount: f32) -> [f32; 3] {
        std::array::from_fn(|i| self.bg[i] + (color[i] - self.bg[i]) * amount)
    }
}

struct Program {
    gl: Gl,
    program: WebGlProgram,
    uniforms: HashMap<&'static str, WebGlUniformLocation>,
}
impl Program {
    fn new(gl: &Gl, vs: &str, fs: &str) -> Result<Self, JsValue> {
        fn shader(gl: &Gl, kind: u32, source: &str) -> Result<WebGlShader, JsValue> {
            let shader = gl
                .create_shader(kind)
                .ok_or_else(|| JsValue::from_str("create shader"))?;
            gl.shader_source(&shader, source);
            gl.compile_shader(&shader);
            if !gl
                .get_shader_parameter(&shader, Gl::COMPILE_STATUS)
                .as_bool()
                .unwrap_or(false)
            {
                let message = gl.get_shader_info_log(&shader).unwrap_or_default();
                gl.delete_shader(Some(&shader));
                return Err(JsValue::from_str(&message));
            }
            Ok(shader)
        }
        let vertex = shader(gl, Gl::VERTEX_SHADER, vs)?;
        let fragment = shader(gl, Gl::FRAGMENT_SHADER, fs)?;
        let program = gl
            .create_program()
            .ok_or_else(|| JsValue::from_str("create program"))?;
        gl.attach_shader(&program, &vertex);
        gl.attach_shader(&program, &fragment);
        gl.link_program(&program);
        gl.delete_shader(Some(&vertex));
        gl.delete_shader(Some(&fragment));
        if !gl
            .get_program_parameter(&program, Gl::LINK_STATUS)
            .as_bool()
            .unwrap_or(false)
        {
            let message = gl.get_program_info_log(&program).unwrap_or_default();
            gl.delete_program(Some(&program));
            return Err(JsValue::from_str(&message));
        }
        let uniforms = [
            "u_camera",
            "u_view",
            "u_shape",
            "u_state",
            "u_state_width",
            "u_active",
            "u_hover",
            "u_selected",
            "u_colors[0]",
            "u_bg",
            "u_fill",
            "u_accent",
        ]
        .into_iter()
        .filter_map(|name| gl.get_uniform_location(&program, name).map(|u| (name, u)))
        .collect();
        Ok(Self {
            gl: gl.clone(),
            program,
            uniforms,
        })
    }
    fn u(&self, key: &str) -> Option<&WebGlUniformLocation> {
        self.uniforms.get(key)
    }
    #[allow(clippy::too_many_arguments)]
    fn bind(
        &self,
        camera: Camera,
        view: (f64, f64),
        scene: &Scene,
        palette: &Palette,
        colors: &[[f32; 3]],
        active: bool,
        hover: Option<usize>,
        selected: Option<usize>,
        state_width: i32,
    ) {
        let gl = &self.gl;
        gl.use_program(Some(&self.program));
        gl.uniform3f(
            self.u("u_camera"),
            camera.scale(view.0, scene) as f32,
            camera.x as f32,
            camera.y as f32,
        );
        gl.uniform2f(self.u("u_view"), view.0 as f32, view.1 as f32);
        gl.uniform3f(self.u("u_shape"), W as f32, H as f32, COL as f32);
        gl.uniform1i(self.u("u_state"), 0);
        gl.uniform1i(self.u("u_state_width"), state_width);
        gl.uniform1i(self.u("u_active"), i32::from(active));
        gl.uniform1f(self.u("u_hover"), hover.map(|n| n as f32).unwrap_or(-1.));
        gl.uniform1f(
            self.u("u_selected"),
            selected.map(|n| n as f32).unwrap_or(-1.),
        );
        gl.uniform3fv_with_f32_array(self.u("u_colors[0]"), colors.as_flattened());
        gl.uniform3fv_with_f32_array(self.u("u_bg"), &palette.bg);
        gl.uniform3fv_with_f32_array(self.u("u_fill"), &palette.fill);
        gl.uniform3fv_with_f32_array(self.u("u_accent"), &palette.accent);
    }
}
impl Drop for Program {
    fn drop(&mut self) {
        self.gl.delete_program(Some(&self.program));
    }
}

struct Pipeline {
    gl: Gl,
    program: Program,
    vao: WebGlVertexArrayObject,
    mesh: WebGlBuffer,
    instances: WebGlBuffer,
    vertices: i32,
    stride: i32,
    attributes: Vec<(u32, i32, i32)>,
}
impl Pipeline {
    fn new(
        gl: &Gl,
        vs: &str,
        fs: &str,
        mesh: &[f32],
        stride: i32,
        attributes: Vec<(u32, i32, i32)>,
    ) -> Result<Self, JsValue> {
        let program = Program::new(gl, vs, fs)?;
        let vao = gl.create_vertex_array().ok_or(JsValue::NULL)?;
        let vertices = (mesh.len() / 2) as i32;
        let mesh_buffer = gl.create_buffer().ok_or(JsValue::NULL)?;
        let instances = gl.create_buffer().ok_or(JsValue::NULL)?;
        gl.bind_vertex_array(Some(&vao));
        gl.bind_buffer(Gl::ARRAY_BUFFER, Some(&mesh_buffer));
        gl.buffer_data_with_array_buffer_view(
            Gl::ARRAY_BUFFER,
            &Float32Array::from(mesh),
            Gl::STATIC_DRAW,
        );
        gl.enable_vertex_attrib_array(0);
        gl.vertex_attrib_pointer_with_i32(0, 2, Gl::FLOAT, false, 8, 0);
        for &(location, _, _) in &attributes {
            gl.enable_vertex_attrib_array(location);
            gl.vertex_attrib_divisor(location, 1);
        }
        Ok(Self {
            gl: gl.clone(),
            program,
            vao,
            mesh: mesh_buffer,
            instances,
            vertices,
            stride,
            attributes,
        })
    }
    fn upload(&self, data: &[f32]) {
        self.gl.bind_buffer(Gl::ARRAY_BUFFER, Some(&self.instances));
        self.gl.buffer_data_with_array_buffer_view(
            Gl::ARRAY_BUFFER,
            &Float32Array::from(data),
            Gl::STATIC_DRAW,
        );
    }
    fn draw(&self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        let gl = &self.gl;
        gl.bind_vertex_array(Some(&self.vao));
        gl.bind_buffer(Gl::ARRAY_BUFFER, Some(&self.instances));
        for &(location, size, offset) in &self.attributes {
            gl.vertex_attrib_pointer_with_i32(
                location,
                size,
                Gl::FLOAT,
                false,
                self.stride,
                range.start as i32 * self.stride + offset,
            );
        }
        gl.draw_arrays_instanced(Gl::TRIANGLES, 0, self.vertices, range.len() as i32);
    }
}
impl Drop for Pipeline {
    fn drop(&mut self) {
        self.gl.delete_vertex_array(Some(&self.vao));
        self.gl.delete_buffer(Some(&self.mesh));
        self.gl.delete_buffer(Some(&self.instances));
    }
}

pub(super) struct Gpu {
    gl: Gl,
    nodes: Pipeline,
    edges: Pipeline,
    state: WebGlTexture,
    state_width: i32,
    state_height: i32,
    bytes: Vec<u8>,
    timer: bool,
    queries: VecDeque<(u64, WebGlQuery)>,
    pub measured: Option<(u64, f64)>,
    pub geometry_uploads: usize,
    pub state_uploads: usize,
}
impl Gpu {
    pub fn new(canvas: &HtmlCanvasElement, count: usize) -> Result<Self, JsValue> {
        let options = Object::new();
        for (key, value) in [
            ("antialias", JsValue::FALSE),
            ("alpha", JsValue::TRUE),
            ("depth", JsValue::FALSE),
            ("stencil", JsValue::FALSE),
            ("premultipliedAlpha", JsValue::FALSE),
            ("powerPreference", JsValue::from_str("high-performance")),
        ] {
            Reflect::set(&options, &JsValue::from_str(key), &value)?;
        }
        let gl: Gl = canvas
            .get_context_with_context_options("webgl2", &options)?
            .ok_or_else(|| JsValue::from_str("WebGL2 unavailable"))?
            .dyn_into()?;
        let nodes = Pipeline::new(
            &gl,
            include_str!("shaders/node.vert"),
            include_str!("shaders/node.frag"),
            &[0., 0., 1., 0., 0., 1., 0., 1., 1., 0., 1., 1.],
            20,
            vec![(1, 2, 0), (2, 2, 8), (3, 1, 16)],
        )?;
        let mut mesh = Vec::new();
        for i in 0..20 {
            let a = i as f32 / 20.;
            let b = (i + 1) as f32 / 20.;
            mesh.extend_from_slice(&[a, -1., b, -1., a, 1., a, 1., b, -1., b, 1.]);
        }
        mesh.extend_from_slice(&[2., 0., 2., -1., 2., 1.]);
        let edges = Pipeline::new(
            &gl,
            include_str!("shaders/edge.vert"),
            include_str!("shaders/edge.frag"),
            &mesh,
            32,
            vec![(1, 4, 0), (2, 4, 16)],
        )?;
        let state = gl.create_texture().ok_or(JsValue::NULL)?;
        let maximum = gl
            .get_parameter(Gl::MAX_TEXTURE_SIZE)?
            .as_f64()
            .unwrap_or(1024.) as usize;
        let width = maximum.min(1024);
        let height = count.max(1).div_ceil(width);
        if height > maximum {
            return Err(JsValue::from_str("Graph exceeds state texture capacity"));
        }
        gl.active_texture(Gl::TEXTURE0);
        gl.bind_texture(Gl::TEXTURE_2D, Some(&state));
        gl.pixel_storei(Gl::UNPACK_ALIGNMENT, 1);
        for (name, value) in [
            (Gl::TEXTURE_MIN_FILTER, Gl::NEAREST),
            (Gl::TEXTURE_MAG_FILTER, Gl::NEAREST),
            (Gl::TEXTURE_WRAP_S, Gl::CLAMP_TO_EDGE),
            (Gl::TEXTURE_WRAP_T, Gl::CLAMP_TO_EDGE),
        ] {
            gl.tex_parameteri(Gl::TEXTURE_2D, name, value as i32);
        }
        let bytes = vec![0; width * height];
        gl.tex_image_2d_with_i32_and_i32_and_i32_and_format_and_type_and_opt_u8_array(
            Gl::TEXTURE_2D,
            0,
            Gl::R8UI as i32,
            width as i32,
            height as i32,
            0,
            Gl::RED_INTEGER,
            Gl::UNSIGNED_BYTE,
            Some(&bytes),
        )?;
        gl.enable(Gl::BLEND);
        gl.blend_func(Gl::SRC_ALPHA, Gl::ONE_MINUS_SRC_ALPHA);
        gl.disable(Gl::DEPTH_TEST);
        let timer = gl
            .get_extension("EXT_disjoint_timer_query_webgl2")?
            .is_some();
        Ok(Self {
            gl,
            nodes,
            edges,
            state,
            state_width: width as i32,
            state_height: height as i32,
            bytes,
            timer,
            queries: VecDeque::new(),
            measured: None,
            geometry_uploads: 0,
            state_uploads: 0,
        })
    }
    pub fn scene(&mut self, scene: &Scene) {
        let mut nodes = Vec::with_capacity(scene.nodes.len() * 5);
        for (i, n) in scene.nodes.iter().enumerate() {
            nodes.extend_from_slice(&[
                n.x as f32,
                n.y as f32,
                scene.ids[i] as f32,
                kind_index(&n.kind) as f32,
                match n.kind.as_str() {
                    "svc-account" | "policy" => 1.,
                    "instance" => 2.,
                    _ => 0.,
                },
            ]);
        }
        self.nodes.upload(&nodes);
        let mut edges = Vec::with_capacity(scene.edges.len() * 8);
        for e in &scene.edges {
            edges.extend_from_slice(&[
                e.from.0 as f32,
                e.from.1 as f32,
                e.to.0 as f32,
                e.to.1 as f32,
                e.src as f32,
                e.dst as f32,
                e.tone as f32,
                e.dash,
            ]);
        }
        self.edges.upload(&edges);
        self.geometry_uploads += 1;
    }
    pub fn state(&mut self, active: Option<&[u8]>) -> Result<(), JsValue> {
        self.bytes.fill(0);
        if let Some(active) = active {
            self.bytes[..active.len()].copy_from_slice(active);
        }
        self.gl.active_texture(Gl::TEXTURE0);
        self.gl.bind_texture(Gl::TEXTURE_2D, Some(&self.state));
        self.gl
            .tex_sub_image_2d_with_i32_and_i32_and_u32_and_type_and_opt_u8_array(
                Gl::TEXTURE_2D,
                0,
                0,
                0,
                self.state_width,
                self.state_height,
                Gl::RED_INTEGER,
                Gl::UNSIGNED_BYTE,
                Some(&self.bytes),
            )?;
        self.state_uploads += 1;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn draw(
        &mut self,
        scene: &Scene,
        visible: &Visible,
        camera: Camera,
        view: (f64, f64),
        pixels: (u32, u32),
        palette: &Palette,
        active: bool,
        hover: Option<usize>,
        selected: Option<usize>,
        frame: u64,
    ) -> usize {
        let gl = &self.gl;
        let query = if self.timer && self.queries.len() < 4 {
            gl.create_query()
        } else {
            None
        };
        if let Some(query) = &query {
            gl.begin_query(0x88bf, query);
        }
        gl.viewport(0, 0, pixels.0 as i32, pixels.1 as i32);
        gl.clear_color(0., 0., 0., 0.);
        gl.clear(Gl::COLOR_BUFFER_BIT);
        gl.active_texture(Gl::TEXTURE0);
        gl.bind_texture(Gl::TEXTURE_2D, Some(&self.state));
        self.edges.program.bind(
            camera,
            view,
            scene,
            palette,
            &palette.edges,
            active,
            hover,
            selected,
            self.state_width,
        );
        for range in &visible.edges {
            self.edges.draw(range.clone());
        }
        self.nodes.program.bind(
            camera,
            view,
            scene,
            palette,
            &palette.nodes,
            active,
            hover,
            selected,
            self.state_width,
        );
        for range in &visible.nodes {
            self.nodes.draw(range.clone());
        }
        if let Some(query) = query {
            gl.end_query(0x88bf);
            self.queries.push_back((frame, query));
        }
        visible.edges.len() + visible.nodes.len()
    }
    pub fn poll(&mut self) -> bool {
        if self.timer
            && self
                .gl
                .get_parameter(0x8fbb)
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            for (_, q) in self.queries.drain(..) {
                self.gl.delete_query(Some(&q));
            }
            self.measured = None;
            return false;
        }
        while let Some((frame, q)) = self.queries.front() {
            if !self
                .gl
                .get_query_parameter(q, Gl::QUERY_RESULT_AVAILABLE)
                .as_bool()
                .unwrap_or(false)
            {
                break;
            }
            if let Some(ns) = self.gl.get_query_parameter(q, Gl::QUERY_RESULT).as_f64() {
                self.measured = Some((*frame, ns / 1_000_000.));
            }
            self.gl.delete_query(Some(q));
            self.queries.pop_front();
        }
        !self.queries.is_empty()
    }
}
impl Drop for Gpu {
    fn drop(&mut self) {
        for (_, q) in self.queries.drain(..) {
            self.gl.delete_query(Some(&q));
        }
        self.gl.delete_texture(Some(&self.state));
    }
}
