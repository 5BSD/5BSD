/* Actual UCL parser/selection transaction; issuer/helper calls are mocked.
 * This proves no genuine kernel domain or cross-domain page isolation. */
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include "../library_cache_policy.c"

struct switchboard_state sd;
static unsigned creates, seeds, publishes, closes, live, fail_create, fail_seed, fail_publish;
static int bound, first_control, first_backing;

int
svc_cache_domain_create(int issuer, int cache, const char *layout,
    const char *signature, struct svc_cache_domain *out)
{
	assert(issuer==91&&cache==92);
	assert(strcmp(layout,"/same.layout")==0&&strcmp(signature,"/same.sig")==0);
	creates++;
	if(creates==fail_create){errno=EIO;return -1;}
	out->control_fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
	out->backing_fd=open("/dev/null",O_RDONLY|O_CLOEXEC);
	assert(out->control_fd>=0&&out->backing_fd>=0);
	if(live==0){first_control=out->control_fd;first_backing=out->backing_fd;}
	else assert(out->control_fd!=first_control&&out->backing_fd!=first_backing);
	live++;return 0;
}
void
svc_cache_domain_close(struct svc_cache_domain *domain)
{
	if(domain->control_fd>=0){assert(close(domain->control_fd)==0);assert(close(domain->backing_fd)==0);closes++;live--;}
	*domain=(struct svc_cache_domain){-1,-1};
}
int
svc_cache_domain_publish(int issuer,const struct svc_cache_domain *domain)
{
	assert(issuer==91&&fcntl(domain->control_fd,F_GETFD)>=0);
	publishes++;if(publishes==fail_publish){errno=EIO;return -1;}return 0;
}
int
svc_cache_domain_bind(int issuer,const struct svc_cache_domain *domain,int token,bool seed)
{
	assert(issuer==91&&token==93&&!seed);bound=domain->control_fd;return 0;
}
static int
mock_seed(int issuer,struct svc_cache_domain *domain,char **libraries,unsigned count)
{
	seeds++;assert(count==1&&strcmp(libraries[0],"libfixture.so.1")==0);
	/* Staged domains must never leak into broker selection during preparation. */
	for(unsigned d=0;d<nselected;d++)assert(selected[d].domain.control_fd!=domain->control_fd);
	if(seeds==fail_seed){errno=ETIMEDOUT;return -1;}
	return svc_cache_domain_publish(issuer,domain);
}
static int
configure(const char *text)
{
	struct ucl_parser *parser=ucl_parser_new(UCL_PARSER_NO_FILEVARS|UCL_PARSER_DISABLE_MACRO);
	assert(parser);assert(ucl_parser_add_string(parser,text,strlen(text)));
	ucl_object_t *root=ucl_parser_get_object(parser);assert(root);
	int result=configure_domains(root,92,mock_seed),saved=errno;
	ucl_object_unref(root);ucl_parser_free(parser);errno=saved;return result;
}
static void
reject_before_create(const char *text)
{
	unsigned before=creates;struct cache_domain_policy *old=selected;unsigned oldn=nselected;
	assert(configure(text)==-1);assert(creates==before&&selected==old&&nselected==oldn);
}
#define SPEC(s) "layout=\"/same.layout\";signature=\"/same.sig\";services=[\"" s "\"];libraries=[\"libfixture.so.1\"];"
int
main(void)
{
	sd.authority_issuer_fd=91;
	assert(configure("enabled=false;")==0&&nselected==0&&creates==0);
	assert(configure("enabled=true;" SPEC("system.Test/leader"))==0);
	assert(nselected==1&&live==1&&creates==1&&publishes==1);
	reject_before_create("enabled=true;domains=[];");
	reject_before_create("enabled=true;domains=[{" SPEC("a") "}];" SPEC("b"));
	reject_before_create("enabled=true;enabled=true;" SPEC("a"));
	reject_before_create("enabled=true;unknown=true;" SPEC("a"));
	reject_before_create("enabled=true;domains=[{" SPEC("a") "unknown=true;}];");
	reject_before_create("enabled=true;domains=[{" SPEC("a") "},{" SPEC("a") "}];");
	reject_before_create("enabled=true;layout=\"relative\";signature=\"/same.sig\";services=[\"a\"];libraries=[\"x\"];");
	reject_before_create("enabled=true;layout=\"/same.layout\";signature=\"/same.sig\";services=[\"a\",\"a\"];libraries=[\"x\"];");
	reject_before_create("enabled=true;layout=\"/same.layout\";signature=\"/same.sig\";services=[\"a\\u0000b\"];libraries=[\"x\"];");
	reject_before_create("enabled=true;layout=\"/same.layout\\u0000other\";signature=\"/same.sig\";services=[\"a\"];libraries=[\"x\"];");
	reject_before_create("enabled=true;layout=\"/same.layout\";signature=\"/same.sig\";services=[\"a\"];libraries=[\"../x\"];");
	reject_before_create("enabled=true;domains=[{" SPEC("a") "},42];");
	char excess[16384], item[256];
	strlcpy(excess,"enabled=true;domains=[",sizeof(excess));
	for(unsigned i=0;i<9;i++) {
		snprintf(item,sizeof(item),"{layout=\"/same.layout\";signature=\"/same.sig\";services=[\"s%u\"];libraries=[\"libfixture.so.1\"];},",i);
		strlcat(excess,item,sizeof(excess));
	}
	strlcat(excess,"];",sizeof(excess));reject_before_create(excess);
	strlcpy(excess,"enabled=true;domains=[{layout=\"/same.layout\";signature=\"/same.sig\";libraries=[\"libfixture.so.1\"];services=[",sizeof(excess));
	for(unsigned i=0;i<64;i++) {snprintf(item,sizeof(item),"\"s%u\",",i);strlcat(excess,item,sizeof(excess));}
	strlcat(excess,"]},{" SPEC("overflow") "}];",sizeof(excess));reject_before_create(excess);
	reject_before_create("enabled=true;layout=\"/same.layout\";signature=\"/same.sig\";services=[\"a\"];libraries=[\"x\",\"x\"];");
	reject_before_create("enabled=true;domains=[{" SPEC("a") "layout=\"/other.layout\";}];");
	const char *two="enabled=true;domains=[{" SPEC("system.Test/leader") "},{" SPEC("system.Test/foreign") "}];";
	struct cache_domain_policy *old=selected;unsigned oldc=closes;
	fail_create=creates+2;assert(configure(two)==-1&&errno==EIO);
	assert(selected==old&&nselected==1&&live==1&&closes==oldc+1);fail_create=0;
	oldc=closes;fail_seed=seeds+2;assert(configure(two)==-1&&errno==ETIMEDOUT);
	assert(selected==old&&nselected==1&&live==1&&closes==oldc+2);fail_seed=0;
	oldc=closes;fail_publish=publishes+2;assert(configure(two)==-1&&errno==EIO);
	assert(selected==old&&nselected==1&&live==1&&closes==oldc+2);fail_publish=0;
	assert(configure(two)==0&&nselected==2&&live==2);
	assert(selected[0].domain.control_fd!=selected[1].domain.control_fd);
	assert(selected[0].domain.backing_fd!=selected[1].domain.backing_fd);
	struct svc_runtime *svc=calloc(1,sizeof(*svc));assert(svc);svc->owner_uid=(uid_t)-1;
	strlcpy(svc->manifest.label,"system.Test/leader",sizeof(svc->manifest.label));
	assert(svc_library_cache_policy_bind(svc,93)==0&&bound==selected[0].domain.control_fd);
	strlcpy(svc->manifest.label,"system.Test/foreign",sizeof(svc->manifest.label));
	assert(svc_library_cache_policy_bind(svc,93)==0&&bound==selected[1].domain.control_fd);
	bound=-1;svc->owner_uid=1001;assert(svc_library_cache_policy_bind(svc,93)==0&&bound==-1);
	svc->owner_uid=(uid_t)-1;strlcpy(svc->manifest.label,"system.Test/unbound",sizeof(svc->manifest.label));
	assert(svc_library_cache_policy_bind(svc,93)==0&&bound==-1);free(svc);
	assert(configure("enabled=false;")==0&&nselected==0&&selected==NULL&&live==0);
	puts("PASS parser rejection before creation, isolated domain selection, staged failure cleanup, personal exclusion (mock issuer/helper)");
	return 0;
}
