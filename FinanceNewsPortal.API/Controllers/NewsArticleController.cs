﻿using FinanceNewsPortal.API.Data;
using FinanceNewsPortal.API.DTO;
using FinanceNewsPortal.API.Enums;
using FinanceNewsPortal.API.Helper;
using FinanceNewsPortal.API.Models;
using FinanceNewsPortal.API.Repository.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FinanceNewsPortal.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class NewsArticleController : ControllerBase
    {
        private readonly INewsArticlesRepository _newsArticlesRepository;
        private readonly FileUpload _fileUpload;

        public NewsArticleController(INewsArticlesRepository newsArticlesRepository,
                                        FileUpload fileUpload)
        {
            this._newsArticlesRepository = newsArticlesRepository;
            this._fileUpload = fileUpload;
        }

        [HttpGet("All")]
        public async Task<IActionResult> GetNewsArticles([FromQuery] int? pageNumber, [FromQuery] int? pageSize)
        {
            List<NewsArticle> newsArticles = await this._newsArticlesRepository.GetNewsArticles(pageNumber ?? 1, pageSize ?? 10);
            return Ok(newsArticles);
        }

        [HttpPost("Create")]
        public async Task<IActionResult> CreateNewsArticle([FromForm] UpsertNewsArticleDTO newsArticleDTO)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest();
            }

            NewsArticle newsArticle = new NewsArticle 
            {
                Title = newsArticleDTO.Title,
                Description = newsArticleDTO.Context,
                Status = NewsStatus.Pending
            };

            await this._newsArticlesRepository.CreateNewsArticle(newsArticle);

            return Ok("News Article created successfully.");
        }

        [HttpGet("Get/{newsArticleId:guid}")]
        public async Task<IActionResult> GetNewsArticle([FromRoute] Guid? newsArticleId)
        {
            if(newsArticleId == null)
            {
                return BadRequest("Provide news article ID.");
            }

            NewsArticle news = await this._newsArticlesRepository.GetNewsArticleById((Guid)newsArticleId);

            return Ok(news);
        }

        [HttpPut("Update")]
        public async Task<IActionResult> UpdateNewsArticle([FromForm] UpsertNewsArticleDTO newsArticleDTO)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest();
            }

            Guid tempUserGuid = Guid.NewGuid();

            if (newsArticleDTO.Image != null)
            {
                // Find the news article with the image file path
                NewsArticle newsArticleWithImageFilePath = await this._newsArticlesRepository
                    .GetNewsArticleImageFilePathById((Guid)newsArticleDTO.Id, tempUserGuid);

                // Delete image file
                this._fileUpload.DeleteFile(newsArticleWithImageFilePath.ImageFilePath, "news-image");

                // Upload file and take generated filename
                newsArticleDTO.ImageFilePath = this._fileUpload.UploadFile(newsArticleDTO.Image, tempUserGuid.ToString(), "news-image");
            }

            newsArticleDTO.Author = tempUserGuid;
            await this._newsArticlesRepository.UpdateNewsArticle((Guid)newsArticleDTO.Id, newsArticleDTO);

            return Ok("News Article updated successfully.");
        }

        [HttpDelete("Delete/{newsArticleId:guid}")]
        public async Task<IActionResult> DeleteNewsArticle([FromRoute] Guid? newsArticleId)
        {
            if(newsArticleId == null)
            {
                return BadRequest("Provide news article ID.");
            }

            var news = await this._newsArticlesRepository.GetNewsArticleById((Guid)newsArticleId);

            if (news == null)
            {
                return NotFound("News article not found.");
            }

            await this._newsArticlesRepository.DeleteNewsArticle((Guid)newsArticleId);

            return Ok("News Article deleted successfully.");
        }
    }
}
