/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <libgeom.h>
#include <err.h>
#include <string.h>
int main(void) {
    struct gmesh mesh;
    const char xml[] = "<mesh><class id='1'><name>TEST</name>"
        "<geom id='2'><class ref='1'/><name>disk</name><rank>1</rank>"
        "<provider id='3'><geom ref='2'/><name>disk0</name>"
        "<mediasize>1048576</mediasize><sectorsize>512</sectorsize>"
        "<config><label>native&amp;test</label></config></provider></geom>"
        "<geom id='4'><class ref='1'/><name>partition</name><rank>2</rank>"
        "<consumer id='5'><geom ref='4'/><provider ref='3'/><mode>r1w0e0</mode>"
        "</consumer></geom></class></mesh>";
    if (geom_xml2tree(&mesh, xml) != 0) errx(1, "parse topology");
    struct gclass *cl = LIST_FIRST(&mesh.lg_class);
    if (!cl || strcmp(cl->lg_name, "TEST") || LIST_NEXT(cl, lg_class)) errx(1, "class");
    struct ggeom *g, *disk = NULL, *partition = NULL;
    LIST_FOREACH(g, &cl->lg_geom, lg_geom) {
        if (g->lg_class != cl) errx(1, "class reference");
        if (!strcmp(g->lg_name, "disk")) disk = g;
        if (!strcmp(g->lg_name, "partition")) partition = g;
    }
    if (!disk || !partition || disk->lg_rank != 1 || partition->lg_rank != 2) errx(1, "geoms");
    struct gprovider *p = LIST_FIRST(&disk->lg_provider);
    struct gconsumer *c = LIST_FIRST(&partition->lg_consumer);
    if (!p || !c || p->lg_geom != disk || c->lg_geom != partition || c->lg_provider != p ||
        LIST_FIRST(&p->lg_consumers) != c) errx(1, "provider/consumer references");
    if (strcmp(p->lg_name, "disk0") || p->lg_mediasize != 1048576 || p->lg_sectorsize != 512)
        errx(1, "provider fields");
    struct gconfig *cfg = LIST_FIRST(&p->lg_config);
    if (!cfg || strcmp(cfg->lg_name, "label") || strcmp(cfg->lg_val, "native&test")) errx(1, "configuration");
    geom_deletetree(&mesh);
    return 0;
}
