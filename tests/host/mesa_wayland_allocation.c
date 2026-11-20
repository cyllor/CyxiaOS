/* Fault injection around the actual retained Mesa Wayland buffer functions.
 * Protocol/allocation fixtures exercise publication and failure sequencing;
 * this host seam does not certify real EGL, GPU rendering or Wayland IPC. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <limits.h>
#define EGL_TRUE 1
#define EGL_FALSE 0
#define EGL_BAD_ALLOC 0x3003
#define EGL_BAD_NATIVE_WINDOW 0x300b
#define BUFFER_TRIM_AGE_HYSTERESIS 20
#define ARRAY_SIZE(x) ((int)(sizeof(x)/sizeof((x)[0])))
#define MIN2(a,b) ((a)<(b)?(a):(b))
typedef int EGLBoolean;
typedef int EGLint;
typedef struct dri2_egl_display _EGLDisplay;
typedef struct dri2_egl_surface _EGLSurface;
struct dri_drawable { int unused; };
struct wl_buffer { int unused; };
struct buffer { struct { struct wl_buffer *buffer; } wayland_buffer;
                bool locked; int age; void *data; int data_size; };
struct window { int width,height,dx,dy; };
struct dri2_egl_display { void *wl_dpy; };
struct dri2_egl_surface {
 struct { struct { _EGLDisplay *Display; } Resource; int Width,Height; } base;
 struct window *wl_win;
 struct buffer *back,*current,color_buffers[4];
 int format,dx,dy; void *wl_queue,*dri_drawable;
 struct { void *wrapper; } wayland_surface;
};
static bool deny_allocation;
static int attempts,commits,attaches,errors,last_error,swaps;
static char destination[256],pixels[256];
static struct wl_buffer token;
static int wl_buffer_listener;
static EGLBoolean _eglError(int error,const char *message) { ++errors;last_error=error;return EGL_FALSE; }
static struct dri2_egl_display *dri2_egl_display(_EGLDisplay *display) { return display; }
static struct dri2_egl_surface *dri2_egl_surface(_EGLSurface *surface) { return surface; }
static int dri2_wl_swrast_get_stride_for_format(int format,int width) { return width*4; }
static EGLBoolean dri2_wl_swrast_allocate_buffer(struct dri2_egl_surface *s,int format,
 int width,int height,void **data,int *size,struct wl_buffer **buffer) {
 ++attempts;if(deny_allocation)return EGL_FALSE;
 *data=destination;*size=width*height*4;*buffer=&token;return EGL_TRUE;
}
static void dri2_wl_release_buffers(struct dri2_egl_surface *surface) { memset(surface->color_buffers,0,sizeof(surface->color_buffers)); }
static void wl_display_dispatch_queue_pending(void *display,void *queue) {}
static void wl_buffer_add_listener(struct wl_buffer *buffer,void *listener,void *data) {}
static int loader_wayland_dispatch(void *display,void *queue,void *data) { return -1; }
static void loader_wayland_buffer_destroy(void *buffer) {}
static bool dri2_wl_surface_throttle(struct dri2_egl_surface *surface) { return true; }
static void wl_surface_attach(void *surface,struct wl_buffer *buffer,int x,int y) { ++attaches; }
static bool try_damage_buffer(struct dri2_egl_surface *surface,const int *rectangles,int count) { return true; }
static void wl_surface_damage(void *surface,int x,int y,int w,int h) {}
static void dri2_wl_swrast_commit_backbuffer(struct dri2_egl_surface *surface) { ++commits; }
static void dri2_wl_swrast_put_image2(struct dri_drawable *,int,int,int,int,int,int,char *,void *);
static void driSwapBuffers(void *drawable) {
 ++swaps;struct dri2_egl_surface *s=drawable;
 dri2_wl_swrast_put_image2(NULL,0,0,0,s->base.Width,s->base.Height,s->base.Width*4,pixels,s);
}
static void driSwapBuffersWithDamage(void *drawable,int count,const int *rectangles) { driSwapBuffers(drawable); }

/* MESA_FUNCTIONS */

#define CHECK(x,message) do { if(!(x)) { fprintf(stderr,"FAIL %s\n",message);return 1; } } while(0)
int main(int argc,char **argv) {
 CHECK(argc==2,"fixture mode required");
 struct window window={.width=4,.height=4};struct dri2_egl_display display={0};
 struct dri2_egl_surface s={.base={.Resource={.Display=&display},.Width=4,.Height=4},.wl_win=&window};s.dri_drawable=&s;
 memset(pixels,0x59,sizeof(pixels));deny_allocation=true;
 if(!strcmp(argv[1],"rollback")) {
  CHECK(swrast_update_buffers(&s)==-1,"allocation must fail");
  CHECK(!s.back && !s.current && !s.color_buffers[0].locked,"failed allocation published a back buffer");
 } else if(!strcmp(argv[1],"retry")) {
  CHECK(swrast_update_buffers(&s)==-1,"first allocation must fail");
  CHECK(swrast_update_buffers(&s)==-1 && attempts==2,"retry reused failed backing as success");
 } else if(!strcmp(argv[1],"late_callback")) {
  CHECK(swrast_update_buffers(&s)==-1,"allocation must fail");
  dri2_wl_swrast_put_image2(NULL,0,0,0,4,4,16,pixels,&s);
  CHECK(last_error==EGL_BAD_ALLOC && !swaps && !commits,"late loader callback lost failure");
 } else if(!strcmp(argv[1],"swap_damage")) {
  CHECK(dri2_wl_swrast_swap_buffers_with_damage(&display,&s,NULL,0)==EGL_FALSE,"damage swap hid allocation failure");
  CHECK(last_error==EGL_BAD_ALLOC && !commits && !attaches && !swaps,"failed swap submitted a frame");
 } else if(!strcmp(argv[1],"swap")) {
  CHECK(dri2_wl_swrast_swap_buffers(&display,&s)==EGL_FALSE,"ordinary swap hid allocation failure");
  CHECK(last_error==EGL_BAD_ALLOC && !commits && !attaches && !swaps,"failed ordinary swap submitted a frame");
 } else if(!strcmp(argv[1],"recover")) {
  CHECK(dri2_wl_swrast_swap_buffers(&display,&s)==EGL_FALSE,"initial swap must fail");
  deny_allocation=false;
  CHECK(dri2_wl_swrast_swap_buffers(&display,&s)==EGL_TRUE,"available backing must recover");
  CHECK(commits==1 && attaches==1 && swaps==1 && !memcmp(destination,pixels,64),"recovery did not copy and submit real bytes");
 } else if(!strcmp(argv[1],"healthy")) {
  deny_allocation=false;
  CHECK(dri2_wl_swrast_swap_buffers(&display,&s)==EGL_TRUE,"healthy swap failed");
  CHECK(commits==1 && !errors && !memcmp(destination,pixels,64),"healthy copy changed");
 } else return 2;
 puts("MESA_WAYLAND_ALLOCATION PASS");return 0;
}
