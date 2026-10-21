#version 300 es
precision highp float;
precision highp int;
layout(location=0) in vec2 a_corner;
layout(location=1) in vec2 a_position;
layout(location=2) in vec2 a_data;
layout(location=3) in float a_dash;
uniform vec3 u_camera;
uniform vec2 u_view;
uniform vec3 u_shape;
out vec2 v_local;
flat out int v_id;
flat out int v_color;
flat out float v_dash;
void main() {
  v_local=a_corner*(u_shape.xy+4.0)-2.0;
  vec2 p=(a_position+v_local)*u_camera.x+u_camera.yz;
  gl_Position=vec4(p/u_view*vec2(2.0,-2.0)+vec2(-1.0,1.0),0.0,1.0);
  v_id=int(a_data.x);v_color=int(a_data.y);v_dash=a_dash;
}
